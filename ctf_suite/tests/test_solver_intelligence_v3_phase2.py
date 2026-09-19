import concurrent.futures
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from ctf_core.downloaders.manager import DownloadManager
from ctf_core.execution.restricted_executor import RestrictedLocalExecutor
from ctf_core.execution.runner import ExecutionRunner
from ctf_core.experiments import (
    EvidenceEvaluator,
    ExecutionAction,
    ExecutionResult,
    Experiment,
    ExperimentCandidate,
    ExperimentEvaluation,
    ExperimentLedger,
    ExperimentPlanner,
    Hypothesis,
    HypothesisManager,
    SolverProgressTracker,
)
from ctf_core.models import AdvisorGuidance, AdvisorResult, Challenge, SubmitResult
from ctf_core.runtime.manager import RuntimeManager
from ctf_core.services.advisor_service import AdvisorService
from ctf_core.services.submit_service import SubmitService


class TestSolverIntelligenceV3Phase2(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root_path = Path(self.temp_dir.name)
        self.runtime_manager = RuntimeManager(base_dir=self.root_path / ".runtime")
        self.event_id = "test_event_v3_p2"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_concurrent_ledger_creation_produces_unique_sequential_ids(self):
        """Invariant: Concurrent creators can never receive the same canonical EXP-xxx ID."""
        advisor_dir = self.root_path / ".advisor_concurrent"
        advisor_dir.mkdir(parents=True, exist_ok=True)
        ledger = ExperimentLedger(advisor_dir)

        num_threads = 10

        def create_entry(idx: int):
            local_ledger = ExperimentLedger(advisor_dir)
            return local_ledger.create(
                hypothesis_id=f"H{idx}",
                intent=f"Concurrent experiment {idx}",
                actions=[ExecutionAction(kind="read_file", path="input:target.txt")],
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(create_entry, i) for i in range(1, num_threads + 1)]
            created_exps = [f.result() for f in futures]

        assigned_ids = [e.experiment_id for e in created_exps]
        # All assigned IDs must be unique
        self.assertEqual(len(assigned_ids), len(set(assigned_ids)))
        self.assertEqual(len(assigned_ids), num_threads)
        # IDs must be sequentially ordered from EXP-001 to EXP-010
        expected_ids = {f"EXP-{i:03d}" for i in range(1, num_threads + 1)}
        self.assertEqual(set(assigned_ids), expected_ids)

    def test_concurrent_flag_submission_idempotency_atomic_reservation(self):
        """Invariant: Concurrent workers submitting same flag execute exactly 1 HTTP submission."""
        mock_platform = MagicMock()
        mock_platform.submit_flag.return_value = {"status": "correct", "message": "Flag accepted"}

        submit_service = SubmitService(
            runtime_manager=self.runtime_manager,
            event_id=self.event_id,
            platform=mock_platform,
            flag_format=r"^FLAG\{.+\}$",
        )

        num_workers = 5
        challenge_id = "chall_race_1"
        flag = "FLAG{concurrent_safe_submission}"

        def do_submit():
            return submit_service.submit(challenge_id=challenge_id, flag=flag, strict=True)

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(do_submit) for _ in range(num_workers)]
            results = [f.result() for f in futures]

        # Exactly ONE call reached the platform
        self.assertEqual(mock_platform.submit_flag.call_count, 1)

        # All submitters received a successful verdict
        for r in results:
            self.assertIn(r.verdict, ["correct", "already_solved", "pending"])

        # Plaintext flag must NOT appear in submitted_flags.jsonl
        ledger_path = self.runtime_manager.event_path(self.event_id) / ".submitted_flags.jsonl"
        self.assertTrue(ledger_path.exists())
        ledger_content = ledger_path.read_text(encoding="utf-8")
        self.assertNotIn("FLAG{concurrent_safe_submission}", ledger_content)

    def test_bounded_io_oversized_stdout_truncation_metadata(self):
        """Invariant: Oversized stdout is bounded and flagged with stdout_truncated=True."""
        work_dir = self.root_path / "work_bounded"
        input_dir = self.root_path / "input_bounded"
        work_dir.mkdir(parents=True, exist_ok=True)
        input_dir.mkdir(parents=True, exist_ok=True)

        # Create a python script that prints 600 KB of output (limit is 512 KB)
        huge_script = work_dir / "huge_output.py"
        huge_script.write_text(
            "import sys\n"
            "sys.stdout.write('A' * (600 * 1024))\n"
        )

        executor = RestrictedLocalExecutor()
        ctx = {
            "challenge_id": "test_bounded_stdout",
            "work_dir": work_dir,
            "input_dir": input_dir,
            "experiment_id": "EXP-001",
        }
        guidance = AdvisorGuidance(
            assessment="Run huge output script",
            is_structured=True,
            execution_plan=[ExecutionAction(kind="run_python_file", path="huge_output.py")],
        )

        res = executor.execute(ctx, guidance)
        self.assertTrue(res.stdout_truncated)
        self.assertFalse(res.output_complete)
        # Captured tail must be bounded
        self.assertLessEqual(len(res.stdout_tail), 1500)

    def test_bounded_downloader_oversized_attachment_aborts_and_removes_partial(self):
        """Invariant: Downloader aborts when file exceeds max size and deletes .part file."""
        dm = DownloadManager()
        target_dir = self.root_path / "downloads"
        target_dir.mkdir(parents=True, exist_ok=True)
        dest_file = target_dir / "oversized.bin"

        # Mock httpx client streaming more bytes than MAX_ATTACHMENT_BYTES
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Length": "100000"}
        # Stream chunks
        mock_resp.iter_bytes.return_value = [b"A" * 1024 for _ in range(50)]

        mock_client = MagicMock()
        mock_client.stream.return_value.__enter__.return_value = mock_resp

        # Limit to 10 KB
        ok = dm._stream_download(
            client=mock_client,
            url="https://ctf.example.com/oversized.bin",
            dest_file=dest_file,
            max_bytes=10 * 1024,
        )
        self.assertFalse(ok)
        self.assertFalse(dest_file.exists())
        part_file = dest_file.with_name(f"{dest_file.name}.part")
        self.assertFalse(part_file.exists())

    def test_challenge_metadata_injection_cannot_alter_solver_structure(self):
        """Invariant: Malicious strings with quotes/newlines in metadata cannot inject code."""
        malicious_chall = Challenge(
            id=1337,
            name='Vuln"\nimport os\nos.system("echo PWNED")\n#',
            category="Pwn",
            connection_info='nc localhost 1337"\nos.system("PWNED")\n#',
        )

        cpath = self.runtime_manager.materialize_challenge(self.event_id, malicious_chall)
        solve_path = cpath / "work" / "solve.py"
        self.assertTrue(solve_path.exists())

        content = solve_path.read_text(encoding="utf-8")
        # Ensure the file compiles as valid Python syntax without executing injected code
        compile(content, str(solve_path), "exec")
        # Ensure host and name literals were safely quoted with json.dumps
        self.assertIn('HOST = "localhost"', content)
        self.assertNotIn('\nos.system("echo PWNED")', content)

    def test_full_production_closed_loop_regression_with_candidates_and_planner(self):
        """
        Full production integration test:
        Advisor candidates -> Planner selection -> Canonical EXP-001 ->
        RestrictedLocalExecutor -> EvidenceEvaluator -> Hypothesis update.
        """
        chall = Challenge(
            id="p2_full_loop",
            name="Phase 2 Full Loop Challenge",
            category="Pwn",
            connection_info="nc localhost 9999",
        )
        cpath = self.runtime_manager.materialize_challenge(self.event_id, chall)
        input_dir = cpath / "input"
        work_dir = cpath / "work"
        (input_dir / "target.txt").write_text("FLAG{phase2_autonomous_loop_verified}")

        advisor_service = AdvisorService(
            workspace_dir=self.root_path,
            runtime_manager=self.runtime_manager,
            event_id=self.event_id,
        )
        advisor_service.init_challenge_advisor(chall.id)

        # Advisor proposes 2 candidates: H1 (Stack overflow) and H2 (Format string)
        consult_response = """```json
        {
            "assessment": "Investigate target file for markers",
            "hypotheses": [
                {"id": "H1", "statement": "File contains target flag"},
                {"id": "H2", "statement": "File contains error message"}
            ],
            "experiment_candidates": [
                {
                    "hypothesis_id": "H1",
                    "intent": "Read target file looking for flag",
                    "expected_evidence": ["FLAG{phase2_autonomous_loop_verified}"],
                    "execution_plan": [
                        {"kind": "read_file", "path": "input:target.txt"}
                    ],
                    "estimated_cost_class": "low"
                },
                {
                    "hypothesis_id": "H2",
                    "intent": "Disallowed tool test",
                    "execution_plan": [
                        {"kind": "analysis_tool", "tool": "rm", "argv": ["rm", "-rf", "/"]}
                    ],
                    "estimated_cost_class": "high"
                }
            ]
        }
        ```"""

        mock_adv_res = AdvisorResult(
            status="READY",
            raw_response=consult_response,
            session_id="session_123",
            provider="oracle",
        )
        with patch.object(advisor_service.advisor_provider, "consult", return_value=mock_adv_res):
            consult_res = advisor_service.consult(chall.id)

        self.assertEqual(consult_res["status"], "READY")
        # Planner should have chosen H1 (since H2 has disallowed tool 'rm')
        active_exp_id = consult_res["active_experiment_id"]
        self.assertEqual(active_exp_id, "EXP-001")

        # Execute selected candidate using RestrictedLocalExecutor
        executor = RestrictedLocalExecutor(flag_format_regex=r"FLAG\{[^\}]+\}")
        ctx = {
            "challenge_id": chall.id,
            "work_dir": work_dir,
            "input_dir": input_dir,
            "experiment_id": active_exp_id,
        }
        exec_result = executor.execute(ctx, consult_res["guidance"])
        self.assertEqual(exec_result.experiment_id, "EXP-001")
        self.assertIn("FLAG{phase2_autonomous_loop_verified}", exec_result.flag_candidates)

        # Report execution back to advisor
        report_res = advisor_service.report_execution(chall.id, exec_result)
        self.assertEqual(report_res["status"], "FLAG_FOUND")

        # Verify hypothesis manager updated H1 to confirmed
        hypo_mgr = HypothesisManager.load(cpath / ".advisor" / "hypotheses.json")
        h1 = hypo_mgr.get("H1")
        self.assertEqual(h1.status, "confirmed")

        # Verify progress tracker recorded new evidence
        tracker = SolverProgressTracker(cpath / ".advisor")
        self.assertGreater(tracker.progress.new_evidence_count, 0)
        self.assertEqual(tracker.progress.rounds_with_zero_new_evidence, 0)


if __name__ == "__main__":
    unittest.main()
