import concurrent.futures
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from ctf_core.downloaders.manager import DownloadManager
from ctf_core.execution.process_runner import StreamingProcessRunner
from ctf_core.execution.policy import ExecutionCapabilities
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
from ctf_core.experiments.signatures import compute_material_signature, compute_context_fingerprint
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

    def test_causal_binding_candidate_index_1_selected_and_executed(self):
        """
        Required Regression Test (Section 1 & 2):
        Advisor proposes:
          Candidate 0: H2, action: read input:a.txt, expected: "A_MARKER"
          Candidate 1: H1, action: read input:b.txt, expected: "B_MARKER"
        Because H1 is active, Planner selects Candidate 1 (index 1).
        Assert:
          - Canonical EXP-001.hypothesis_id == "H1"
          - Canonical EXP-001 actions refer to b.txt
          - Executor actually reads b.txt
          - Execution evidence includes B_MARKER
          - Execution evidence does NOT include A_MARKER
          - report_execution mutates H1 only
          - H2 remains unchanged
          - ExecutionResult.experiment_id == EXP-001
        """
        cid = "chall_causal_regress"
        chall = Challenge(id=cid, name="CausalRegressionToy", category="Pwn")
        cpath = self.runtime_manager.materialize_challenge(self.event_id, chall)
        input_dir = cpath / "input"
        work_dir = cpath / "work"

        # Prepare a.txt and b.txt
        (input_dir / "a.txt").write_text("A_MARKER\n", encoding="utf-8")
        (input_dir / "b.txt").write_text("B_MARKER\n", encoding="utf-8")

        advisor_service = AdvisorService(
            workspace_dir=self.root_path,
            runtime_manager=self.runtime_manager,
            event_id=self.event_id,
        )
        advisor_service.init_challenge_advisor(chall.id)

        # Set H1 as active hypothesis in hypothesis manager
        hypo_file = cpath / ".advisor" / "hypotheses.json"
        hypo_mgr = HypothesisManager(max_consecutive_failures=2)
        h1 = Hypothesis(id="H1", statement="Hypothesis 1 (Active)", status="active")
        h2 = Hypothesis(id="H2", statement="Hypothesis 2 (Proposed)", status="proposed")
        hypo_mgr.register([h1, h2])
        hypo_mgr.activate("H1")
        hypo_mgr.save(hypo_file)

        # Advisor response has Candidate 0 = H2 (lower priority), Candidate 1 = H1 (active, higher priority)
        advisor_json = """```json
        {
            "assessment": "Test causal candidate selection",
            "hypotheses": [
                {"id": "H1", "statement": "Target is in file B"},
                {"id": "H2", "statement": "Target is in file A"}
            ],
            "experiment_candidates": [
                {
                    "hypothesis_id": "H2",
                    "intent": "Inspect file A",
                    "expected_evidence": ["A_MARKER"],
                    "execution_plan": [
                        {"kind": "read_file", "path": "input:a.txt"}
                    ],
                    "estimated_cost_class": "low"
                },
                {
                    "hypothesis_id": "H1",
                    "intent": "Inspect file B",
                    "expected_evidence": ["B_MARKER"],
                    "execution_plan": [
                        {"kind": "read_file", "path": "input:b.txt"}
                    ],
                    "estimated_cost_class": "low"
                }
            ]
        }
        ```"""

        mock_adv_res = AdvisorResult(
            status="READY",
            raw_response=advisor_json,
            session_id="sess_causal",
            provider="oracle",
        )
        with patch.object(advisor_service.advisor_provider, "consult", return_value=mock_adv_res):
            consult_res = advisor_service.consult(chall.id)

        self.assertEqual(consult_res["status"], "READY")
        active_exp_id = consult_res["active_experiment_id"]
        self.assertEqual(active_exp_id, "EXP-001")

        # Invariant checks on canonical Experiment
        ledger = ExperimentLedger(cpath / ".advisor")
        canonical_exp = ledger.get("EXP-001")
        self.assertIsNotNone(canonical_exp)
        self.assertEqual(canonical_exp.hypothesis_id, "H1")
        self.assertTrue(any("b.txt" in str(act.path or "") for act in canonical_exp.actions_to_run))
        self.assertFalse(any("a.txt" in str(act.path or "") for act in canonical_exp.actions_to_run))

        # Real execution via RestrictedLocalExecutor
        executor = RestrictedLocalExecutor()
        ctx = {
            "challenge_id": chall.id,
            "work_dir": work_dir,
            "input_dir": input_dir,
            "experiment_id": active_exp_id,
            "canonical_experiment": canonical_exp,
            "actions": canonical_exp.actions_to_run,
        }
        exec_result = executor.execute(ctx, consult_res["guidance"])

        self.assertEqual(exec_result.experiment_id, "EXP-001")
        self.assertTrue(any("b.txt" in str(act) for act in exec_result.actions))
        self.assertFalse(any("a.txt" in str(act) for act in exec_result.actions))
        self.assertTrue(any("B_MARKER" in ev for ev in exec_result.evidence))
        self.assertFalse(any("A_MARKER" in ev for ev in exec_result.evidence))

        # Report execution and verify only H1 transitions
        report_res = advisor_service.report_execution(chall.id, exec_result)
        self.assertEqual(report_res["status"], "CONFIRMED")

        updated_hypo_mgr = HypothesisManager.load(hypo_file)
        updated_h1 = updated_hypo_mgr.get("H1")
        updated_h2 = updated_hypo_mgr.get("H2")
        self.assertEqual(updated_h1.status, "confirmed")
        self.assertEqual(updated_h2.status, "proposed")

    def test_streaming_large_stdout_bounded_during_execution(self):
        """Invariant: Large stdout is bounded incrementally; buffer memory stays bounded."""
        work_dir = self.root_path / "work_stream_bound"
        work_dir.mkdir(parents=True, exist_ok=True)
        py_file = work_dir / "gen_huge.py"
        # 1 MB stdout
        py_file.write_text("import sys; sys.stdout.write('X' * (1024 * 1024))\n")

        res = StreamingProcessRunner.run_bounded(
            argv=["python3", str(py_file)],
            cwd=work_dir,
            env={"PATH": os.environ.get("PATH", "/usr/bin")},
            max_stdout_bytes=64 * 1024,
        )
        self.assertTrue(res.stdout_truncated)
        self.assertFalse(res.output_complete)
        self.assertLessEqual(len(res.stdout.encode("utf-8")), 64 * 1024 + 1024)
        self.assertEqual(res.return_code, 0)

    def test_streaming_marker_detected_past_retained_buffer_cutoff(self):
        """Invariant: Target marker located past the retained-buffer cutoff is still detected."""
        work_dir = self.root_path / "work_stream_marker"
        work_dir.mkdir(parents=True, exist_ok=True)
        py_file = work_dir / "gen_marker_late.py"
        # 50 KB padding, then marker, then 50 KB padding
        py_file.write_text(
            "import sys\n"
            "sys.stdout.write('A' * (50 * 1024))\n"
            "sys.stdout.write('DEEP_MARKER_FOUND\\n')\n"
            "sys.stdout.write('B' * (50 * 1024))\n"
        )

        res = StreamingProcessRunner.run_bounded(
            argv=["python3", str(py_file)],
            cwd=work_dir,
            env={"PATH": os.environ.get("PATH", "/usr/bin")},
            max_stdout_bytes=10 * 1024,  # Buffer capped at 10 KB
            target_evidence=["DEEP_MARKER_FOUND"],
        )
        self.assertTrue(res.stdout_truncated)
        self.assertNotIn("DEEP_MARKER_FOUND", res.stdout)
        self.assertIn("DEEP_MARKER_FOUND", res.matched_evidence)

        # Evaluates to CONFIRMED despite truncation because positive evidence was observed
        exp = Experiment(
            experiment_id="EXP-100",
            hypothesis_id="H1",
            intent="Detect deep marker",
            expected_evidence=["DEEP_MARKER_FOUND"],
        )
        exec_res = ExecutionResult(
            experiment_id="EXP-100",
            status="CONFIRMED",
            return_code=0,
            stdout_truncated=res.stdout_truncated,
            output_complete=res.output_complete,
            evidence=res.matched_evidence,
        )
        eval_res = EvidenceEvaluator.evaluate(exp, exec_res)
        self.assertEqual(eval_res.outcome, "confirmed")

    def test_streaming_truncated_missing_marker_evaluates_to_inconclusive(self):
        """Invariant: Never infer absence from truncated output -> outcome is INCONCLUSIVE."""
        exp = Experiment(
            experiment_id="EXP-101",
            hypothesis_id="H1",
            intent="Detect absent marker in truncated stream",
            expected_evidence=["MISSING_TARGET"],
        )
        exec_res = ExecutionResult(
            experiment_id="EXP-101",
            status="INCONCLUSIVE",
            return_code=0,
            stdout_truncated=True,
            output_complete=False,
            evidence=[],
        )
        eval_res = EvidenceEvaluator.evaluate(exp, exec_res)
        self.assertEqual(eval_res.outcome, "inconclusive")
        self.assertNotEqual(eval_res.outcome, "rejected")

    def test_streaming_independent_stderr_bounding(self):
        """Invariant: Massive stderr is bounded independently without affecting stdout."""
        work_dir = self.root_path / "work_stream_stderr"
        work_dir.mkdir(parents=True, exist_ok=True)
        py_file = work_dir / "gen_stderr.py"
        py_file.write_text(
            "import sys\n"
            "sys.stdout.write('NORMAL_STDOUT\\n')\n"
            "sys.stderr.write('E' * (80 * 1024))\n"
        )

        res = StreamingProcessRunner.run_bounded(
            argv=["python3", str(py_file)],
            cwd=work_dir,
            env={"PATH": os.environ.get("PATH", "/usr/bin")},
            max_stdout_bytes=32 * 1024,
            max_stderr_bytes=10 * 1024,
        )
        self.assertFalse(res.stdout_truncated)
        self.assertTrue(res.stderr_truncated)
        self.assertIn("NORMAL_STDOUT", res.stdout)
        self.assertLessEqual(len(res.stderr.encode("utf-8")), 10 * 1024 + 1024)

    def test_same_origin_download_single_body_stream_request(self):
        """Invariant: Same-origin download streams from the first request (ONE body stream, no double GET)."""
        dm = DownloadManager(platform_url="https://ctf.example.com")
        target_dir = self.root_path / "single_stream_dl"
        target_dir.mkdir(parents=True, exist_ok=True)
        dest_file = target_dir / "test.zip"

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.is_redirect = False
        mock_resp.headers = {"Content-Length": "24"}
        mock_resp.iter_bytes.return_value = [b"SINGLE_STREAM_CONTENT_OK"]

        # Track calls to auth_client.stream
        stream_call_count = 0
        def fake_stream(method, url, **kwargs):
            nonlocal stream_call_count
            stream_call_count += 1
            mock_ctx = MagicMock()
            mock_ctx.__enter__.return_value = mock_resp
            mock_ctx.__exit__.return_value = None
            return mock_ctx

        with patch.object(dm.auth_client, "stream", side_effect=fake_stream), \
             patch.object(dm.auth_client, "get") as mock_get:
            out = dm.download_file("https://ctf.example.com/files/test.zip", target_dir)
            self.assertIsNotNone(out)
            # auth_client.get was NEVER called (no unstreamed pre-check)
            mock_get.assert_not_called()
            # auth_client.stream was called exactly ONCE
            self.assertEqual(stream_call_count, 1)

    def test_material_wording_changes_do_not_bypass_retry_suppression(self):
        """Invariant: Natural language intent changes cannot bypass retry suppression."""
        cand_a = ExperimentCandidate(
            hypothesis_id="H1",
            intent="Check canary in binary",
            rationale="Initial check",
            execution_plan=[ExecutionAction(kind="read_file", path="input:bin")],
            expected_evidence=["CANARY_ENABLED"],
        )
        cand_b = ExperimentCandidate(
            hypothesis_id="H1",
            intent="Inspect whether stack protection canary exists",
            rationale="Different wording entirely",
            execution_plan=[ExecutionAction(kind="read_file", path="input:bin")],
            expected_evidence=["CANARY_ENABLED"],
        )

        sig_a = compute_material_signature(cand_a)
        sig_b = compute_material_signature(cand_b)
        self.assertEqual(sig_a, sig_b)

        # In planner: if cand_a was rejected, cand_b is suppressed
        advisor_dir = self.root_path / ".advisor_retry"
        advisor_dir.mkdir(parents=True, exist_ok=True)
        ledger = ExperimentLedger(advisor_dir)
        exp = ledger.create(
            hypothesis_id="H1",
            intent=cand_a.intent,
            actions=cand_a.execution_plan,
            expected_evidence=cand_a.expected_evidence,
        )
        exp.outcome = "rejected"
        ledger.append(exp)

        hypo_mgr = HypothesisManager()
        hypo_mgr.register([Hypothesis(id="H1", statement="Test", status="active")])
        tracker = SolverProgressTracker(advisor_dir)

        planner = ExperimentPlanner()
        sel = planner.select_candidate([cand_b], hypo_mgr, ledger, tracker)
        self.assertIsNone(sel.selected)
        self.assertTrue(any("retry_suppressed" in str(e.rejection_reason) for e in sel.evaluations))

    def test_meaningful_context_change_allows_retry(self):
        """Invariant: Same experiment is eligible again if material context fingerprint changed."""
        cand = ExperimentCandidate(
            hypothesis_id="H1",
            intent="Run solver against target",
            execution_plan=[ExecutionAction(kind="run_solver", path="work:solve.py")],
            expected_evidence=["FLAG_TOKEN"],
        )

        advisor_dir = self.root_path / ".advisor_ctx_retry"
        advisor_dir.mkdir(parents=True, exist_ok=True)
        ledger = ExperimentLedger(advisor_dir)
        # Previous run had context fingerprint "FINGERPRINT_1"
        exp = ledger.create(
            hypothesis_id="H1",
            intent=cand.intent,
            actions=cand.execution_plan,
            expected_evidence=cand.expected_evidence,
            context_fingerprint="FINGERPRINT_1",
        )
        exp.outcome = "rejected"
        ledger.append(exp)

        hypo_mgr = HypothesisManager()
        hypo_mgr.register([Hypothesis(id="H1", statement="Test", status="active")])
        tracker = SolverProgressTracker(advisor_dir)
        planner = ExperimentPlanner()

        # Under same fingerprint "FINGERPRINT_1", retry is suppressed
        sel_same = planner.select_candidate([cand], hypo_mgr, ledger, tracker, context_fingerprint="FINGERPRINT_1")
        self.assertIsNone(sel_same.selected)

        # Under modified fingerprint "FINGERPRINT_2" (e.g. solve.py edited), retry is allowed!
        sel_new = planner.select_candidate([cand], hypo_mgr, ledger, tracker, context_fingerprint="FINGERPRINT_2")
        self.assertIsNotNone(sel_new.selected)
        self.assertEqual(sel_new.selected.hypothesis_id, "H1")

    def test_first_inconclusive_preserves_active_hypothesis_priority_within_budget(self):
        """Invariant: First INCONCLUSIVE does not demote active hypothesis below proposed alternatives."""
        hypo_mgr = HypothesisManager(max_consecutive_failures=2)
        h1 = Hypothesis(id="H1", statement="Active primary hypothesis", status="active", failure_count=0)
        h2 = Hypothesis(id="H2", statement="Alternative proposed hypothesis", status="proposed")
        hypo_mgr.register([h1, h2])
        hypo_mgr.activate("H1")

        # H1 yields 1st inconclusive
        eval_inconclusive = ExperimentEvaluation(
            experiment_id="EXP-001",
            outcome="inconclusive",
            reason="Output incomplete",
        )
        hypo_mgr.apply_evaluation("H1", eval_inconclusive)
        self.assertEqual(h1.status, "inconclusive")
        self.assertEqual(h1.failure_count, 1)
        self.assertFalse(hypo_mgr.recommend_pivot())

        # Planner evaluates candidates for H2 and H1
        cand_h2 = ExperimentCandidate(
            hypothesis_id="H2",
            intent="Try alternative",
            execution_plan=[ExecutionAction(kind="read_file", path="input:h2.txt")],
        )
        cand_h1 = ExperimentCandidate(
            hypothesis_id="H1",
            intent="Refine active hypothesis",
            execution_plan=[ExecutionAction(kind="read_file", path="input:h1_refined.txt")],
        )

        advisor_dir = self.root_path / ".advisor_budget"
        advisor_dir.mkdir(parents=True, exist_ok=True)
        ledger = ExperimentLedger(advisor_dir)
        tracker = SolverProgressTracker(advisor_dir)
        planner = ExperimentPlanner()

        sel = planner.select_candidate([cand_h2, cand_h1], hypo_mgr, ledger, tracker)
        # H1 must remain preferred because it is within failure budget!
        self.assertIsNotNone(sel.selected)
        self.assertEqual(sel.selected.hypothesis_id, "H1")

        # Now H1 yields 2nd inconclusive, exhausting budget
        hypo_mgr.apply_evaluation("H1", eval_inconclusive)
        self.assertEqual(h1.failure_count, 2)
        self.assertTrue(hypo_mgr.recommend_pivot())

        # Now proposed H2 becomes preferred
        sel_after_pivot = planner.select_candidate([cand_h2, cand_h1], hypo_mgr, ledger, tracker)
        self.assertIsNotNone(sel_after_pivot.selected)
        self.assertEqual(sel_after_pivot.selected.hypothesis_id, "H2")

    def test_stagnation_resets_on_new_evidence_transition_and_pivot(self):
        """Invariant: Stagnation consecutive window resets upon new evidence, hypothesis transition, or pivot."""
        advisor_dir = self.root_path / ".advisor_stag"
        advisor_dir.mkdir(parents=True, exist_ok=True)
        tracker = SolverProgressTracker(advisor_dir)

        # 3 zero-progress rounds -> stagnated
        tracker.record_evidence([])
        tracker.record_evidence([])
        tracker.record_evidence([])
        self.assertTrue(tracker.is_stagnated(threshold=3))

        # Reset via new evidence
        tracker.record_evidence(["NEW_PRIMITIVE_OBSERVED"])
        self.assertFalse(tracker.is_stagnated(threshold=3))

        # Stagnate again
        tracker.record_evidence([])
        tracker.record_evidence([])
        tracker.record_evidence([])
        self.assertTrue(tracker.is_stagnated(threshold=3))

        # Reset via hypothesis transition
        tracker.record_hypothesis_transition()
        self.assertFalse(tracker.is_stagnated(threshold=3))

        # Stagnate again
        tracker.record_evidence([])
        tracker.record_evidence([])
        tracker.record_evidence([])
        self.assertTrue(tracker.is_stagnated(threshold=3))

        # Reset via pivot
        tracker.record_pivot()
        self.assertFalse(tracker.is_stagnated(threshold=3))

    def test_fallback_solver_malicious_metadata_compiles_safely(self):
        """Invariant: Fallback solver generation safely quotes malicious metadata and persists JSON context."""
        malicious_chall = Challenge(
            id="evil_chall",
            name='Test"\'\nimport os\nos.system("echo PWN")\n{eval(1+1)}#\'\'\'"""',
            category="category_without_template_xyz",
            connection_info='nc evil.host 1234"\n#',
        )

        cpath = self.runtime_manager.materialize_challenge(self.event_id, malicious_chall)
        solve_py = cpath / "work" / "solve.py"
        ctx_json = cpath / "work" / "challenge_context.json"

        self.assertTrue(solve_py.exists())
        self.assertTrue(ctx_json.exists())

        code = solve_py.read_text(encoding="utf-8")
        # Must compile as valid Python without SyntaxError
        compiled = compile(code, str(solve_py), "exec")
        self.assertIsNotNone(compiled)

        # Structured context contains the exact malicious string as pure data
        data = json.loads(ctx_json.read_text(encoding="utf-8"))
        self.assertIn("echo PWN", data["name"])

    def test_evidence_cannot_cross_bind_between_candidates(self):
        """Invariant: Evidence from Candidate A cannot be attributed to an experiment for Candidate B."""
        cid = "chall_cross_bind"
        chall = Challenge(id=cid, name="CrossBindTest", category="Pwn")
        cpath = self.runtime_manager.materialize_challenge(self.event_id, chall)
        input_dir = cpath / "input"
        work_dir = cpath / "work"

        # Candidate A searches for MARKER_A in a.txt, Candidate B searches for MARKER_B in b.txt
        (input_dir / "a.txt").write_text("MARKER_A_CONTENT\n", encoding="utf-8")
        (input_dir / "b.txt").write_text("MARKER_B_CONTENT\n", encoding="utf-8")

        advisor_service = AdvisorService(
            workspace_dir=self.root_path,
            runtime_manager=self.runtime_manager,
            event_id=self.event_id,
        )
        advisor_service.init_challenge_advisor(chall.id)

        hypo_file = cpath / ".advisor" / "hypotheses.json"
        hypo_mgr = HypothesisManager(max_consecutive_failures=2)
        h1 = Hypothesis(id="H1", statement="Hypothesis 1 (Active)", status="active")
        h2 = Hypothesis(id="H2", statement="Hypothesis 2 (Proposed)", status="proposed")
        hypo_mgr.register([h1, h2])
        hypo_mgr.activate("H1")
        hypo_mgr.save(hypo_file)

        # Advisor returns Candidate 0 for H2 and Candidate 1 for H1
        advisor_json = """```json
        {
            "assessment": "Test cross-binding prevention",
            "hypotheses": [
                {"id": "H1", "statement": "Target B"},
                {"id": "H2", "statement": "Target A"}
            ],
            "experiment_candidates": [
                {
                    "hypothesis_id": "H2",
                    "intent": "Read A",
                    "expected_evidence": ["MARKER_A_CONTENT"],
                    "execution_plan": [{"kind": "read_file", "path": "input:a.txt"}]
                },
                {
                    "hypothesis_id": "H1",
                    "intent": "Read B",
                    "expected_evidence": ["MARKER_B_CONTENT"],
                    "execution_plan": [{"kind": "read_file", "path": "input:b.txt"}]
                }
            ]
        }
        ```"""

        mock_adv_res = AdvisorResult(
            status="READY",
            raw_response=advisor_json,
            session_id="sess_cross",
            provider="oracle",
        )
        with patch.object(advisor_service.advisor_provider, "consult", return_value=mock_adv_res):
            consult_res = advisor_service.consult(chall.id)

        active_exp_id = consult_res["active_experiment_id"]
        self.assertEqual(active_exp_id, "EXP-001")

        # Execute
        executor = RestrictedLocalExecutor()
        ledger = ExperimentLedger(cpath / ".advisor")
        canonical_exp = ledger.get(active_exp_id)
        ctx = {
            "challenge_id": chall.id,
            "work_dir": work_dir,
            "input_dir": input_dir,
            "experiment_id": active_exp_id,
            "canonical_experiment": canonical_exp,
            "actions": canonical_exp.actions_to_run,
        }
        exec_result = executor.execute(ctx, consult_res["guidance"])

        # Invariant: Evidence is strictly B, never A
        self.assertTrue(any("MARKER_B_CONTENT" in ev for ev in exec_result.evidence))
        self.assertFalse(any("MARKER_A_CONTENT" in ev for ev in exec_result.evidence))

        # Report execution and assert only H1 receives outcome and mutation
        advisor_service.report_execution(chall.id, exec_result)
        updated_hypo_mgr = HypothesisManager.load(hypo_file)
        self.assertEqual(updated_hypo_mgr.get("H1").status, "confirmed")
        self.assertEqual(updated_hypo_mgr.get("H2").status, "proposed")
        self.assertEqual(updated_hypo_mgr.get("H2").failure_count, 0)

    def test_canonical_exp_actions_strictly_govern_executed_actions(self):
        """Invariant: Canonical Experiment actions are the sole execution authority, ignoring divergent guidance."""
        work_dir = self.root_path / "work_canon_auth"
        input_dir = self.root_path / "input_canon_auth"
        work_dir.mkdir(parents=True, exist_ok=True)
        input_dir.mkdir(parents=True, exist_ok=True)

        canonical_action = ExecutionAction(kind="read_file", path="input:canonical_target.txt")
        canonical_exp = Experiment(
            experiment_id="EXP-042",
            hypothesis_id="H1",
            intent="Authoritative action execution",
            execution_plan=[canonical_action],
        )

        divergent_action = ExecutionAction(kind="read_file", path="input:divergent_target.txt")
        guidance = AdvisorGuidance(
            is_structured=True,
            execution_plan=[divergent_action],
        )

        ctx = {
            "work_dir": work_dir,
            "input_dir": input_dir,
            "experiment_id": "EXP-042",
            "canonical_experiment": canonical_exp,
        }

        # ExecutionRunner.resolve_actions_to_run MUST prioritize canonical_experiment
        resolved = ExecutionRunner.resolve_actions_to_run(
            guidance=guidance,
            work_dir=work_dir,
            challenge_context=ctx,
        )
        self.assertEqual(len(resolved), 1)
        self.assertEqual(resolved[0].path, "input:canonical_target.txt")
        self.assertNotEqual(resolved[0].path, "input:divergent_target.txt")

    def test_cross_origin_redirect_strips_credentials(self):
        """Invariant: Same-origin redirect to cross-origin URL switches to anon_client and strips auth headers."""
        dm = DownloadManager(
            platform_url="https://ctf.example.com",
            session_cookie="secret_session=12345",
            api_token="super_secret_token",
        )
        target_dir = self.root_path / "cross_dl"
        target_dir.mkdir(parents=True, exist_ok=True)
        dest_file = target_dir / "attachment.zip"

        # 1st request: same-origin returns 302 redirect to AWS S3
        mock_302_resp = MagicMock()
        mock_302_resp.is_redirect = True
        mock_302_resp.headers = {"Location": "https://s3.amazonaws.com/files/attachment.zip"}

        # 2nd request: external origin returns 200 with data
        mock_200_resp = MagicMock()
        mock_200_resp.is_redirect = False
        mock_200_resp.status_code = 200
        mock_200_resp.headers = {"Content-Length": "20"}
        mock_200_resp.iter_bytes.return_value = [b"S3_ATTACHMENT_BYTES!"]

        def fake_stream(method, url, **kwargs):
            mock_ctx = MagicMock()
            if "ctf.example.com" in url:
                mock_ctx.__enter__.return_value = mock_302_resp
            else:
                mock_ctx.__enter__.return_value = mock_200_resp
            mock_ctx.__exit__.return_value = None
            return mock_ctx

        with patch.object(dm.auth_client, "stream", side_effect=fake_stream) as mock_auth_stream, \
             patch.object(dm.anon_client, "stream", side_effect=fake_stream) as mock_anon_stream:
            out = dm.download_file(
                "https://ctf.example.com/api/v1/download/1",
                target_dir,
                suggested_name="attachment.zip",
            )
            self.assertIsNotNone(out)
            self.assertEqual(out, dest_file)
            self.assertTrue(dest_file.exists())
            self.assertEqual(dest_file.read_bytes(), b"S3_ATTACHMENT_BYTES!")

            # Auth client called for initial same-origin request
            mock_auth_stream.assert_called_once()
            # Anonymous client called for cross-origin redirect
            mock_anon_stream.assert_called_once()
            # anon_client headers contain NO Cookie or Authorization
            self.assertNotIn("Cookie", dm.anon_client.headers)
            self.assertNotIn("Authorization", dm.anon_client.headers)

    def test_container_timeout_triggers_cleanup(self):
        """Invariant: Child process timeout invokes container kill and removal cleanup."""
        work_dir = self.root_path / "work_timeout_clean"
        work_dir.mkdir(parents=True, exist_ok=True)
        py_file = work_dir / "sleep_proc.py"
        py_file.write_text("import time\ntime.sleep(10)\n")

        with patch.object(StreamingProcessRunner, "_cleanup_container") as mock_cleanup:
            res = StreamingProcessRunner.run_bounded(
                argv=["python3", str(py_file)],
                cwd=work_dir,
                env={"PATH": os.environ.get("PATH", "/usr/bin")},
                timeout=1,
                cleanup_container_name="test-sandbox-cleanup-123",
            )
            self.assertTrue(res.timed_out)
            mock_cleanup.assert_called_once_with("test-sandbox-cleanup-123")

    def test_planner_capability_filtering_with_execution_capabilities(self):
        """Invariant: Planner rejects candidates exceeding executor capabilities before canonicalization."""
        caps = ExecutionCapabilities(
            supported_action_kinds=["read_file", "run_solver", "run_sage_file", "analysis_tool"],
            allowed_analysis_tools=["checksec"],
            available_analysis_tools=["checksec"],
            sage_available=False,
        )
        planner = ExperimentPlanner(capabilities=caps)

        # Candidate requesting unavailable SageMath
        cand_sage = ExperimentCandidate(
            hypothesis_id="H1",
            intent="Run sage solve",
            execution_plan=[ExecutionAction(kind="run_sage_file", path="solve.sage")],
        )
        ok_sage, err_sage = planner.is_executable(cand_sage)
        self.assertFalse(ok_sage)
        self.assertIn("sage is unavailable", err_sage)

        # Candidate requesting unsupported action kind (run_binary not in supported_action_kinds)
        cand_bad_kind = ExperimentCandidate(
            hypothesis_id="H1",
            intent="Run binary when unsupported",
            execution_plan=[ExecutionAction(kind="run_binary", path="vuln")],
        )
        ok_bad_kind, err_bad_kind = planner.is_executable(cand_bad_kind)
        self.assertFalse(ok_bad_kind)
        self.assertIn("unsupported kind", err_bad_kind)

        # Candidate requesting uninstalled analysis tool 'ropper'
        cand_ropper = ExperimentCandidate(
            hypothesis_id="H1",
            intent="Run ropper",
            execution_plan=[ExecutionAction(kind="analysis_tool", tool="ropper", argv=["ropper", "--file", "vuln"])],
        )
        ok_ropper, err_ropper = planner.is_executable(cand_ropper)
        self.assertFalse(ok_ropper)
        self.assertIn("disallowed analysis tool", err_ropper)

        # Valid candidate requesting read_file
        cand_valid = ExperimentCandidate(
            hypothesis_id="H1",
            intent="Read target",
            execution_plan=[ExecutionAction(kind="read_file", path="input:flag.txt")],
        )
        ok_valid, err_valid = planner.is_executable(cand_valid)
        self.assertTrue(ok_valid)
        self.assertIsNone(err_valid)


if __name__ == "__main__":
    unittest.main()

