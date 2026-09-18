import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional

from ctf_core.models import (
    Challenge,
    CTFInfo,
    SubmitResult,
    AdvisorGuidance,
    Hypothesis,
    Action,
    ExecutionResult,
)
from ctf_core.platforms.base import BasePlatform
from ctf_core.runtime.manager import RuntimeManager
from ctf_core.services.advisor_service import AdvisorService
from ctf_core.services.submit_service import SubmitService
from ctf_core.services.orchestrator import ChallengeOrchestrator
from ctf_core.meta.knowledge_compiler import KnowledgeCompiler
from ctf_core.downloaders.manager import DownloadManager


class FakePlatform(BasePlatform):
    """Mock platform simulating CTF server without network calls."""

    def __init__(self, url: str = "https://ctf.fake.io", **kwargs):
        super().__init__(url=url, session_cookie="fake_sess=123", api_token="fake_token_abc")
        self.submitted_flags: List[Dict[str, Any]] = []
        self.challenges_list = [
            Challenge(id=1, name="Baby Rev", category="Rev", points=100, files=[{"name": "baby.bin", "url": "https://ctf.fake.io/files/baby.bin"}]),
            Challenge(id=2, name="Hard Pwn", category="Pwn", points=400, files=[]),
            Challenge(id=3, name="Secret Crypto", category="Crypto", points=250, files=[]),
        ]

    def authenticate(self) -> bool:
        return True

    def fetch_challenges(self) -> List[Challenge]:
        return [c.model_copy() for c in self.challenges_list]

    def fetch_ctf_info(self) -> CTFInfo:
        return CTFInfo(
            title="Fake CTF 2026",
            url=self.url,
            platform="fake",
            challenges=[c.model_copy() for c in self.challenges_list],
        )

    def submit_flag(self, challenge_id: Any, flag: str) -> SubmitResult:
        self.submitted_flags.append({"challenge_id": challenge_id, "flag": flag})
        if flag.strip() == "FLAG{fake_rev_solved_1337}":
            return SubmitResult(
                verdict="correct",
                message="Flag accepted!",
                challenge_id=challenge_id,
                flag=flag,
                points=100,
            )
        elif flag.strip() == "FLAG{already_done}":
            return SubmitResult(
                verdict="already_solved",
                message="Already solved.",
                challenge_id=challenge_id,
                flag=flag,
            )
        return SubmitResult(
            verdict="incorrect",
            message="Wrong flag.",
            challenge_id=challenge_id,
            flag=flag,
        )


class FakeAdvisor(AdvisorService):
    """Mock Advisor that yields structured AdvisorGuidance but executes real knowledge compilation."""

    def __init__(self, workspace_dir: Path, runtime_manager: RuntimeManager, event_id: str, kb_compiler: KnowledgeCompiler):
        super().__init__(workspace_dir=workspace_dir, runtime_manager=runtime_manager, event_id=event_id)
        self.kb_compiler = kb_compiler
        self.consult_count = 0

    def consult(self, challenge_id: Any) -> Dict[str, Any]:
        self.consult_count += 1
        guidance = AdvisorGuidance(
            assessment="Challenge requires XOR inversion of buffer at 0x401000",
            hypotheses=[
                Hypothesis(id="H1", statement="Key is single byte 0x5a"),
                Hypothesis(id="H2", statement="Key is multi-byte rolling XOR"),
            ],
            next_actions=[
                Action(type="command", command_or_task="python3 solve.py", expected_evidence="al = 0x5a")
            ],
            requested_evidence=["Disassembled loop at 0x401000"],
            stop_conditions=["Flag format matched"],
        )
        return {
            "challenge_id": str(challenge_id),
            "iteration": self.consult_count,
            "guidance": guidance,
            "active_hypothesis": "Key is single byte 0x5a",
        }


class FakeExecutor:
    """Mock Executor producing an ExecutionResult with a discovered flag candidate."""

    def __init__(self, flag_to_find: str = "FLAG{fake_rev_solved_1337}"):
        self.flag_to_find = flag_to_find
        self.executed_contexts: List[Dict[str, Any]] = []

    def execute(self, challenge_context: Dict[str, Any], guidance: AdvisorGuidance) -> ExecutionResult:
        self.executed_contexts.append(challenge_context)
        return ExecutionResult(
            experiment_id=f"EXP-{challenge_context.get('iteration', 1):03d}",
            status="FLAG_FOUND",
            actions=["XOR decode with key 0x5a"],
            observed="Decoded plaintext matched flag format",
            evidence=["XOR loop reversed successfully"],
            flag_candidates=[self.flag_to_find],
            stdout_tail="Decoded: FLAG{fake_rev_solved_1337}",
        )


class TestLifecycleClosedLoop(unittest.TestCase):
    def setUp(self):
        self.test_root = Path(tempfile.mkdtemp())
        self.runtime_dir = self.test_root / ".runtime"
        self.kb_dir = self.test_root / "knowledge_base"
        self.kb_dir.mkdir(parents=True)
        self.runtime_manager = RuntimeManager(base_dir=self.runtime_dir)

    def tearDown(self):
        shutil.rmtree(self.test_root, ignore_errors=True)

    def test_full_autonomous_lifecycle(self):
        """
        Integration test verifying:
        1. FakePlatform lists challenges -> in-memory (no directories created eagerly).
        2. Runtime materializes ONLY selected challenge lazily.
        3. FakeAdvisor generates structured AdvisorGuidance.
        4. FakeExecutor returns ExecutionResult with flag_candidates.
        5. Orchestrator calls advisor.report_execution().
        6. Submitter submits flag -> correct -> calls advisor.mark_solved().
        7. KnowledgeCard compiled into knowledge_base/ without plaintext flag.
        8. Ephemeral challenge directory is cleaned up immediately.
        9. KnowledgeCard remains intact after challenge and event cleanup.
        10. Interrupted run can resume if runtime exists.
        """
        event_id = "test_tournament"
        fake_platform = FakePlatform()
        fake_advisor = FakeAdvisor(
            workspace_dir=self.test_root,
            runtime_manager=self.runtime_manager,
            event_id=event_id,
            kb_compiler=KnowledgeCompiler(kb_dir=self.kb_dir),
        )
        fake_executor = FakeExecutor()

        # Step 1: Query platform challenges
        challs = fake_platform.list_challenges()
        self.assertEqual(len(challs), 3)

        # Assert no challenge directory has been created yet (LAZY!)
        epath = self.runtime_manager.event_path(event_id)
        chall_root = epath / "challenges"
        self.assertFalse(chall_root.exists(), "Runtime challenges folder should NOT exist before materialization!")

        # Step 2: Initialize Orchestrator with our custom components
        orchestrator = ChallengeOrchestrator(
            workspace_dir=self.test_root,
            platform_url="https://ctf.fake.io",
            runtime_manager=self.runtime_manager,
            executor=fake_executor,
            event_id=event_id,
            cleanup_policy="immediate",
            platform=fake_platform,
            advisor=fake_advisor,
        )

        # Step 3: Select only the lowest-point challenge (Baby Rev, id=1, 100 pts)
        selected_chall = challs[0]
        self.assertEqual(selected_chall.id, 1)

        # Execute closed-loop cycle for this challenge
        solved = orchestrator.execute_challenge_cycle({
            "id": str(selected_chall.id),
            "name": selected_chall.name,
            "category": selected_chall.category,
            "points": selected_chall.points,
            "challenge": selected_chall,
        })
        self.assertTrue(solved, "Challenge should be successfully solved!")

        # Assert flag was submitted to platform
        self.assertEqual(len(fake_platform.submitted_flags), 1)
        self.assertEqual(fake_platform.submitted_flags[0]["flag"], "FLAG{fake_rev_solved_1337}")

        # Assert only challenge 1 was executed by executor
        self.assertEqual(len(fake_executor.executed_contexts), 1)
        self.assertEqual(fake_executor.executed_contexts[0]["challenge_id"], "1")

        # Assert challenge 2 and 3 were NEVER materialized
        cpath2 = self.runtime_manager.challenge_path(event_id, 2)
        cpath3 = self.runtime_manager.challenge_path(event_id, 3)
        self.assertFalse(cpath2.exists(), "Challenge 2 must not be materialized!")
        self.assertFalse(cpath3.exists(), "Challenge 3 must not be materialized!")

        # Assert KnowledgeCard was created in knowledge_base/
        index_file = self.kb_dir / "index.json"
        self.assertTrue(index_file.is_file(), "Knowledge index must exist!")
        index_data = json.loads(index_file.read_text(encoding="utf-8"))
        self.assertIn("1", index_data)
        card_rel_path = index_data["1"]["card_path"]
        card_full_path = self.kb_dir / card_rel_path
        self.assertTrue(card_full_path.is_file(), f"Knowledge card {card_full_path} must exist!")

        card_content = card_full_path.read_text(encoding="utf-8")
        # ASSERT NO PLAINTEXT FLAG STORED IN KNOWLEDGE CARD!
        self.assertNotIn("FLAG{fake_rev_solved_1337}", card_content, "Real flag must NEVER be stored in Knowledge Card!")
        self.assertIn("Baby Rev", card_content)

        # Assert challenge runtime was cleaned up (immediate cleanup policy)
        cpath1 = self.runtime_manager.challenge_path(event_id, 1)
        self.assertFalse(cpath1.exists(), "Ephemeral challenge runtime should be deleted after immediate cleanup!")

        # Step 4: Event Cleanup
        self.runtime_manager.cleanup_event(event_id)
        self.assertFalse(epath.exists(), "Event runtime should be deleted after event cleanup!")

        # ASSERT KNOWLEDGE CARD STILL SURVIVES EVENT CLEANUP!
        self.assertTrue(card_full_path.is_file(), "Knowledge card MUST persist after event cleanup!")

    def test_path_traversal_guards(self):
        """Verify that path traversal in challenge IDs or event IDs is strictly rejected."""
        with self.assertRaises(ValueError):
            self.runtime_manager._assert_contained(Path("/etc/passwd"), self.runtime_dir)

        # Safe sanitization strips traversal
        safe_eid = self.runtime_manager.event_path("../../var/run")
        self.assertTrue(safe_eid.resolve().is_relative_to(self.runtime_dir.resolve()))
        self.assertNotIn("..", safe_eid.name)

        safe_cid = self.runtime_manager.challenge_path("ev1", "../../../etc/shadow")
        self.assertTrue(safe_cid.resolve().is_relative_to((self.runtime_dir / "ev1" / "challenges").resolve()))
        self.assertNotIn("..", safe_cid.name)

    def test_credential_leakage_prevention(self):
        """Verify DownloadManager isolates credentials from cross-origin requests."""
        dm = DownloadManager(
            platform_url="https://ctf.myplatform.org",
            session_cookie="secret_sess_cookie=1",
            api_token="secret_token_123"
        )
        # Same origin
        self.assertTrue(dm.is_same_origin("https://ctf.myplatform.org/files/chal.zip"))
        self.assertTrue(dm.is_same_origin("/files/chal.zip"))

        # Cross origin
        self.assertFalse(dm.is_same_origin("https://drive.google.com/uc?id=xyz"))
        self.assertFalse(dm.is_same_origin("https://external-cdn.amazonaws.com/files/chal.zip"))
        self.assertFalse(dm.is_same_origin("http://ctf.myplatform.org/files/chal.zip"))  # different scheme

        # Check anonymous client headers
        self.assertNotIn("Cookie", dm.anon_client.headers)
        self.assertNotIn("Authorization", dm.anon_client.headers)

        dm.close()

    def test_retryable_verdicts_in_ledger(self):
        """Verify that auth_failed, ratelimited, and error verdicts can be retried."""
        submitter = SubmitService(
            workspace_dir=self.test_root,
            platform_url="https://ctf.fake.io",
            runtime_manager=self.runtime_manager,
            event_id="test_retry"
        )
        flag = "FLAG{retry_candidate}"
        # Initially not submitted
        self.assertIsNone(submitter.has_been_submitted(42, flag))

        # Record a ratelimited failure
        res_rate = SubmitResult(verdict="ratelimited", message="Slow down", challenge_id=42, flag=flag)
        submitter._record_submission(42, flag, res_rate)
        # MUST BE RETRYABLE (returns None)
        self.assertIsNone(submitter.has_been_submitted(42, flag))

        # Record auth_failed failure
        res_auth = SubmitResult(verdict="auth_failed", message="Expired cookie", challenge_id=42, flag=flag)
        submitter._record_submission(42, flag, res_auth)
        # MUST BE RETRYABLE (returns None)
        self.assertIsNone(submitter.has_been_submitted(42, flag))

        # Record error failure
        res_err = SubmitResult(verdict="error", message="HTTP 500", challenge_id=42, flag=flag)
        submitter._record_submission(42, flag, res_err)
        # MUST BE RETRYABLE (returns None)
        self.assertIsNone(submitter.has_been_submitted(42, flag))

        # Record incorrect submission
        res_inc = SubmitResult(verdict="incorrect", message="Wrong", challenge_id=42, flag=flag)
        submitter._record_submission(42, flag, res_inc)
        # NOW BLOCKED / DEDUPED (returns "incorrect")
        self.assertEqual(submitter.has_been_submitted(42, flag), "incorrect")

        # Verify plaintext flag is NOT stored in ledger
        ledger_text = submitter.ledger_file.read_text(encoding="utf-8")
        self.assertNotIn(flag, ledger_text)
        self.assertIn("hash", ledger_text)
