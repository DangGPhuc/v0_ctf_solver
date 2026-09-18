import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from ctf_core.models import AdvisorGuidance, Hypothesis, Action, ExecutionResult
from ctf_core.execution.restricted_executor import RestrictedLocalExecutor
from ctf_core.execution.unsafe_executor import UnsafeLocalExecutor
from ctf_core.execution import get_executor


class TestExecutorSecurity(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.work_dir = self.test_dir / "work"
        self.input_dir = self.test_dir / "input"
        self.work_dir.mkdir(parents=True)
        self.input_dir.mkdir(parents=True)

        self.context = {
            "challenge_id": "test_1",
            "challenge_dir": self.test_dir,
            "iteration": 1,
            "active_hypothesis": "Test Hypothesis H1",
        }

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_restricted_executor_strips_sensitive_environment_variables(self):
        """RestrictedLocalExecutor MUST strip API_TOKEN, SESSION_COOKIE, etc. from child process."""
        # Create a Python script that outputs specific env vars
        checker_script = self.work_dir / "check_env.py"
        checker_script.write_text(
            "import os\n"
            "print('API_TOKEN=' + os.environ.get('API_TOKEN', 'NOT_FOUND'))\n"
            "print('SESSION_COOKIE=' + os.environ.get('SESSION_COOKIE', 'NOT_FOUND'))\n"
            "print('PATH_EXISTS=' + str('PATH' in os.environ))\n",
            encoding="utf-8"
        )

        # Set dangerous env in parent process
        os.environ["API_TOKEN"] = "super_secret_platform_token"
        os.environ["SESSION_COOKIE"] = "super_secret_cookie"

        try:
            executor = RestrictedLocalExecutor(timeout=10)
            guidance = AdvisorGuidance(
                assessment="Test assessment",
                next_actions=[Action(type="command", command_or_task="python3 check_env.py")]
            )

            result = executor.execute(self.context, guidance)
            self.assertIn("API_TOKEN=NOT_FOUND", result.observed)
            self.assertIn("SESSION_COOKIE=NOT_FOUND", result.observed)
            self.assertIn("PATH_EXISTS=True", result.observed)
        finally:
            os.environ.pop("API_TOKEN", None)
            os.environ.pop("SESSION_COOKIE", None)

    def test_restricted_executor_evidence_based_status(self):
        """Non-empty output without proving hypothesis must yield INCONCLUSIVE, not CONFIRMED."""
        script = self.work_dir / "run_test.py"
        script.write_text("print('Ordinary diagnostic output')", encoding="utf-8")

        executor = RestrictedLocalExecutor(timeout=10)
        guidance = AdvisorGuidance(
            assessment="Test assessment",
            next_actions=[
                Action(
                    type="command",
                    command_or_task="python3 run_test.py",
                    expected_evidence="SPECIFIC_PROOF_STRING"
                )
            ]
        )

        result = executor.execute(self.context, guidance)
        # Expected evidence was NOT found in output -> INCONCLUSIVE
        self.assertEqual(result.status, "INCONCLUSIVE")
        self.assertEqual(result.flag_candidates, [])

    def test_restricted_executor_detects_flag(self):
        """When output matches flag regex, status must be FLAG_FOUND."""
        script = self.work_dir / "find_flag.py"
        script.write_text("print('Found: FLAG{sandbox_escaped_cleanly_1337}')", encoding="utf-8")

        executor = RestrictedLocalExecutor(timeout=10, flag_format=r"^FLAG\{.+\}$")
        guidance = AdvisorGuidance(
            assessment="Test assessment",
            next_actions=[Action(type="command", command_or_task="python3 find_flag.py")]
        )

        result = executor.execute(self.context, guidance)
        self.assertEqual(result.status, "FLAG_FOUND")
        self.assertIn("FLAG{sandbox_escaped_cleanly_1337}", result.flag_candidates)

    def test_restricted_executor_enforces_timeout(self):
        """Long-running script must be killed when exceeding timeout."""
        script = self.work_dir / "sleep_loop.py"
        script.write_text("import time\ntime.sleep(10)\n", encoding="utf-8")

        executor = RestrictedLocalExecutor(timeout=1)  # 1 second timeout
        guidance = AdvisorGuidance(
            assessment="Test assessment",
            next_actions=[Action(type="command", command_or_task="python3 sleep_loop.py")]
        )

        result = executor.execute(self.context, guidance)
        self.assertEqual(result.status, "ERROR")
        self.assertIn("timed out", result.observed.lower())

    def test_get_executor_factory_modes(self):
        """Verify get_executor respects executor modes."""
        # Unsafe local
        unsafe_exec = get_executor(mode="unsafe-local")
        self.assertIsInstance(unsafe_exec, UnsafeLocalExecutor)

        # Restricted local
        restricted_exec = get_executor(mode="restricted-local")
        self.assertIsInstance(restricted_exec, RestrictedLocalExecutor)


if __name__ == "__main__":
    unittest.main()
