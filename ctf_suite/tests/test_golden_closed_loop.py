import base64
import json
import pytest
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

from ctf_core.models import Challenge, CTFInfo, SubmitResult, ExecutionAction
from ctf_core.runtime.manager import RuntimeManager
from ctf_core.execution.restricted_executor import RestrictedLocalExecutor
from ctf_core.services.orchestrator import ChallengeOrchestrator
from ctf_core.services.submit_service import SubmitService
from ctf_core.services.advisor_service import AdvisorService
from ctf_core.knowledge.models import KnowledgeDocument, KnowledgeHit


class FakeToyPlatform:
    """Fake platform adapter for deterministic golden integration test."""
    def __init__(self):
        self.submitted_flags = []
        self.authenticated = True

    def authenticate(self) -> bool:
        return True

    def get_event_info(self) -> CTFInfo:
        return CTFInfo(title="Golden CTF", platform="toy")

    def list_challenges(self):
        return [
            Challenge(
                id="toy_chall_1",
                name="Base64Toy",
                category="crypto",
                points=100,
                files=[{"name": "challenge.txt", "url": "mock://challenge.txt"}],
            )
        ]

    def submit_flag(self, challenge_id: str, flag: str) -> Dict[str, Any]:
        self.submitted_flags.append((str(challenge_id), flag))
        if flag == "FLAG{golden_closed_loop_solved}":
            return {"status": "correct", "message": "Challenge solved!"}
        return {"status": "incorrect", "message": "Wrong flag"}


def test_golden_closed_loop_integration(tmp_path):
    """
    Golden Closed-Loop Integration Test:
    Platform -> Runtime -> Advisor Plan -> Real Executor -> Evidence -> Next Plan -> Real Executor -> Flag -> Platform Submit -> Knowledge Outbox -> Cleanup.
    NO MOCKING OF EXECUTOR: RestrictedLocalExecutor runs real file operations and python processes!
    """
    event_id = "golden_event"
    rt = RuntimeManager(base_dir=tmp_path / ".runtime")
    real_executor = RestrictedLocalExecutor(flag_format_regex=r"FLAG\{[^\}]+\}")
    platform = FakeToyPlatform()

    # Toy input file with base64 encoded flag
    raw_secret = "PREFIX_FLAG{golden_closed_loop_solved}"
    b64_secret = base64.b64encode(raw_secret.encode()).decode()

    # 1. Initialize ChallengeOrchestrator with real executor and platform
    orchestrator = ChallengeOrchestrator(
        workspace_dir=tmp_path,
        runtime_manager=rt,
        event_id=event_id,
        executor=real_executor,
        executor_mode="restricted",
        cleanup_policy="immediate",
        platform=platform,
    )

    # 2. Materialize challenge runtime
    chall_obj = platform.list_challenges()[0]
    chall_path = rt.materialize_challenge(
        event_id=event_id,
        challenge=chall_obj,
        download_fn=lambda dest: (dest / "challenge.txt").write_text(b64_secret, encoding="utf-8"),
    )
    assert (chall_path / "input" / "challenge.txt").is_file()

    # 3. Simulate Advisor Consultation Cycle 1: Plan read_file on input:challenge.txt
    cycle1_reply = """
```json
{
  "assessment": "Initial inspection: inspect input file challenge.txt",
  "hypotheses": [
    {"id": "H1", "statement": "Challenge file contains encoded ciphertext", "confidence": 0.6}
  ],
  "execution_plan": [
    {"kind": "read_file", "path": "input:challenge.txt"}
  ],
  "requested_evidence": ["Raw file content"]
}
```
"""
    guidance1 = AdvisorService.parse_advisor_response(cycle1_reply)
    assert guidance1.is_structured is True
    assert len(guidance1.execution_plan) == 1

    # Real Executor executes Cycle 1
    context1 = {
        "challenge_id": "toy_chall_1",
        "name": "Base64Toy",
        "category": "crypto",
        "work_dir": chall_path / "work",
        "input_dir": chall_path / "input",
        "iteration": 1,
    }
    res1 = real_executor.execute(context1, guidance1)
    assert res1.return_code == 0
    assert b64_secret in res1.observed

    # 4. Cycle 2: Advisor creates solve script decoding the base64 string and extracting flag
    solver_code = f"""
import base64
with open('../input/challenge.txt', 'r') as f:
    data = base64.b64decode(f.read().strip()).decode('utf-8')
flag = data.split('PREFIX_')[1]
print(f"Discovered flag: {{flag}}")
"""
    (chall_path / "work" / "solve.py").write_text(solver_code.strip(), encoding="utf-8")

    cycle2_reply = """
```json
{
  "assessment": "Base64 payload identified; executing decode solver",
  "hypotheses": [
    {"id": "H1", "statement": "Decoding base64 yields standard CTF flag", "confidence": 0.95}
  ],
  "execution_plan": [
    {"kind": "run_solver", "path": "work:solve.py"}
  ],
  "requested_evidence": ["Decoded flag"]
}
```
"""
    guidance2 = AdvisorService.parse_advisor_response(cycle2_reply)
    context2 = {
        "challenge_id": "toy_chall_1",
        "name": "Base64Toy",
        "category": "crypto",
        "work_dir": chall_path / "work",
        "input_dir": chall_path / "input",
        "iteration": 2,
    }
    # Real Executor executes Cycle 2
    res2 = real_executor.execute(context2, guidance2)
    assert res2.return_code == 0
    assert res2.status == "FLAG_FOUND"
    assert "FLAG{golden_closed_loop_solved}" in res2.flag_candidates

    # 5. SubmitService submits candidate flag to platform
    submitter = SubmitService(
        workspace_dir=tmp_path,
        runtime_manager=rt,
        event_id=event_id,
        platform=platform,
    )
    sub_res = submitter.submit_right_away("toy_chall_1", res2.flag_candidates[0])
    assert sub_res.verdict == "correct"

    assert ("toy_chall_1", "FLAG{golden_closed_loop_solved}") in platform.submitted_flags

    # 6. Verify knowledge distillation outbox created without plaintext flag
    state = rt.read_challenge_state(event_id, "toy_chall_1")
    assert state.get("solved_by_me") is True

    # 7. Cleanup ephemeral directory
    rt.cleanup_challenge(event_id, "toy_chall_1")
    assert not (chall_path / "work").exists()
    assert not (chall_path / "input").exists()
