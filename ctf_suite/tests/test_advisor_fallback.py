import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from ctf_core.models import Challenge, AdvisorResult, AdvisorGuidance, Hypothesis, Action, ExecutionResult
from ctf_core.runtime.manager import RuntimeManager
from ctf_core.services.advisor_service import AdvisorService
from ctf_core.services.orchestrator import ChallengeOrchestrator
from ctf_core.platforms.base import BasePlatform


class FakePlatform(BasePlatform):
    def __init__(self):
        super().__init__(url="https://mock.ctf")
    def authenticate(self) -> bool:
        return True
    def fetch_challenges(self):
        return [Challenge(id=1, name="Test Chall", category="Pwn", points=100)]
    def fetch_ctf_info(self):
        return None
    def submit_flag(self, challenge_id, flag):
        return None


class TestAdvisorFallback(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.runtime_manager = RuntimeManager(base_dir=self.test_dir / ".runtime")
        self.event_id = "test_event"

        self.chall = Challenge(id=1, name="Baby Rev", category="Rev", points=100)
        self.runtime_manager.materialize_challenge(self.event_id, self.chall)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_oracle_unavailable_returns_waiting_for_manual_response(self):
        """When Oracle and browser automation fail, consult() must return WAITING_FOR_MANUAL_RESPONSE."""
        advisor = AdvisorService(
            workspace_dir=self.test_dir,
            runtime_manager=self.runtime_manager,
            event_id=self.event_id,
        )

        # Mock browser bridge to simulate opening Firefox and copying prompt (fallback mode)
        advisor.browser_bridge.open_chatgpt_with_prompt = MagicMock(return_value=False)

        result = advisor.consult(1)
        self.assertEqual(result.get("status"), "WAITING_FOR_MANUAL_RESPONSE")
        adv_res = result.get("advisor_result")
        self.assertIsInstance(adv_res, AdvisorResult)
        self.assertEqual(adv_res.status, "WAITING_FOR_MANUAL_RESPONSE")
        self.assertIsNone(result.get("guidance"))

    def test_orchestrator_halts_and_does_not_call_executor_on_manual_response(self):
        """Orchestrator MUST NOT call Executor when Advisor is waiting for manual response."""
        advisor = AdvisorService(
            workspace_dir=self.test_dir,
            runtime_manager=self.runtime_manager,
            event_id=self.event_id,
        )
        # Mock consult to return WAITING_FOR_MANUAL_RESPONSE
        advisor.consult = MagicMock(return_value=AdvisorResult(
            status="WAITING_FOR_MANUAL_RESPONSE",
            provider="browser_manual",
            message="Prompt copied. Waiting for human advice."
        ))

        mock_executor = MagicMock()
        mock_platform = FakePlatform()

        orchestrator = ChallengeOrchestrator(
            workspace_dir=self.test_dir,
            platform_url="https://mock.ctf",
            runtime_manager=self.runtime_manager,
            event_id=self.event_id,
            platform=mock_platform,
            advisor=advisor,
            executor=mock_executor,
        )

        solved = orchestrator.execute_challenge_cycle({
            "id": "1",
            "name": "Baby Rev",
            "category": "Rev",
            "points": 100,
            "challenge": self.chall,
        })

        self.assertFalse(solved)
        # Verify executor was NEVER invoked!
        mock_executor.execute.assert_not_called()

    def test_import_manual_response_resumes_advisor_flow(self):
        """Test importing manual ChatGPT response into runtime .advisor/."""
        advisor = AdvisorService(
            workspace_dir=self.test_dir,
            runtime_manager=self.runtime_manager,
            event_id=self.event_id,
        )
        advisor.init_challenge_advisor(1)

        manual_response_file = self.test_dir / "chatgpt_reply.md"
        manual_response_file.write_text(
            "## Hypotheses\n- H1: Key is XOR with 0x42\n\n## Next Actions\n- python3 solve.py\n\n## Stop Conditions\n- Found flag\n",
            encoding="utf-8"
        )

        success = advisor.import_manual_response(1, manual_response_file)
        self.assertTrue(success)

        guidance_path = advisor.get_advisor_dir(1) / "guidance.md"
        self.assertTrue(guidance_path.is_file())
        self.assertIn("Key is XOR with 0x42", guidance_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
