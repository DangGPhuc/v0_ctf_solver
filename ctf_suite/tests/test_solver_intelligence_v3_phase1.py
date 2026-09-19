import json
from pathlib import Path
import tempfile
import unittest

from ctf_core.advisor.guidance_parser import GuidanceParser
from ctf_core.execution.policy import ActionPolicy
from ctf_core.execution.runner import ExecutionRunner
from ctf_core.experiments import (
    EvidenceEvaluator,
    ExecutionAction,
    ExecutionResult,
    Experiment,
    ExperimentEvaluation,
    ExperimentLedger,
    Hypothesis,
    HypothesisManager,
    HypothesisRecord,
)
from ctf_core.models import AdvisorGuidance
from ctf_core.execution.restricted_executor import RestrictedLocalExecutor
from ctf_core.services.advisor_service import AdvisorService


class TestHypothesisLifecycle(unittest.TestCase):
    """Unit tests for HypothesisManager and hypothesis lifecycle state transitions."""

    def test_hypothesis_lifecycle_transitions(self):
        # 1. Proposed -> Active
        h1 = Hypothesis(id="H1", statement="Binary has stack buffer overflow in vuln()", status="proposed")
        mgr = HypothesisManager(hypotheses=[h1], max_consecutive_failures=2)
        self.assertEqual(mgr.get_active().id, "H1")
        self.assertEqual(mgr.get_active().status, "active")

        # 2. Active -> Confirmed
        eval_confirm = ExperimentEvaluation(
            outcome="confirmed",
            supporting_evidence=["Canary found", "Buffer overflow verified"],
            reason="Canary found at offset 64",
        )
        updated = mgr.apply_evaluation("H1", eval_confirm)
        self.assertEqual(updated.status, "confirmed")
        self.assertEqual(updated.attempts, 1)
        self.assertEqual(updated.failure_count, 0)
        self.assertIn("Canary found", updated.supporting_evidence)
        self.assertTrue(mgr.recommend_pivot())  # Pivot required because H1 reached terminal confirmed state

    def test_hypothesis_lifecycle_rejected(self):
        # Active -> Rejected
        h1 = Hypothesis(id="H1", statement="Binary uses format string vulnerability", status="proposed")
        mgr = HypothesisManager(hypotheses=[h1], max_consecutive_failures=2)
        eval_reject = ExperimentEvaluation(
            outcome="rejected",
            contradicting_evidence=["printf is called with fixed string constant"],
            reason="Format string argument is static format constant",
        )
        updated = mgr.apply_evaluation("H1", eval_reject)
        self.assertEqual(updated.status, "rejected")
        self.assertEqual(updated.attempts, 1)
        self.assertEqual(updated.failure_count, 1)
        self.assertIn("printf is called with fixed string constant", updated.contradicting_evidence)
        self.assertTrue(mgr.recommend_pivot())

    def test_hypothesis_lifecycle_inconclusive_failure_budget(self):
        # Active + Inconclusive -> remains unresolved, attempts incremented
        h1 = Hypothesis(id="H1", statement="Remote server runs vulnerable PHP endpoint", status="proposed")
        mgr = HypothesisManager(hypotheses=[h1], max_consecutive_failures=2)

        # First inconclusive experiment
        eval_inc1 = ExperimentEvaluation(outcome="inconclusive", reason="Tool timed out")
        mgr.apply_evaluation("H1", eval_inc1)
        self.assertEqual(h1.status, "inconclusive")
        self.assertEqual(h1.attempts, 1)
        self.assertEqual(h1.failure_count, 1)
        self.assertFalse(mgr.recommend_pivot())  # Budget not yet exhausted (1 < 2)

        # Second inconclusive experiment
        eval_inc2 = ExperimentEvaluation(outcome="inconclusive", reason="Container network unreachable")
        mgr.apply_evaluation("H1", eval_inc2)
        self.assertEqual(h1.attempts, 2)
        self.assertEqual(h1.failure_count, 2)
        self.assertTrue(mgr.recommend_pivot())  # Budget exhausted (2 >= 2)


class TestExperimentLedger(unittest.TestCase):
    """Unit tests for canonical append-only ExperimentLedger."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.advisor_dir = Path(self.temp_dir.name) / ".advisor"
        self.advisor_dir.mkdir(parents=True, exist_ok=True)
        self.ledger = ExperimentLedger(self.advisor_dir)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_ledger_append_read_stable_ids(self):
        exp1 = self.ledger.create(
            hypothesis_id="H1",
            intent="Check checksec protections",
            actions=[ExecutionAction(kind="analysis_tool", tool="checksec", argv=["checksec", "--file=vuln"])],
            expected_evidence=["Canary found"],
        )
        self.assertEqual(exp1.experiment_id, "EXP-001")
        self.assertEqual(exp1.outcome, "pending")

        exp2 = self.ledger.create(
            hypothesis_id="H1",
            intent="Inspect strings for flag format",
            actions=[ExecutionAction(kind="analysis_tool", tool="strings", argv=["strings", "vuln"])],
        )
        self.assertEqual(exp2.experiment_id, "EXP-002")

        # Read back from ledger
        all_exps = self.ledger.list_all()
        self.assertEqual(len(all_exps), 2)
        self.assertEqual(all_exps[0].experiment_id, "EXP-001")
        self.assertEqual(all_exps[1].experiment_id, "EXP-002")

    def test_ledger_result_update_and_recent(self):
        exp = self.ledger.create(
            hypothesis_id="H1",
            intent="Read flag file",
            expected_evidence=["CTF{test}"],
        )
        eval_res = ExperimentEvaluation(
            outcome="confirmed",
            supporting_evidence=["CTF{test}"],
            reason="Flag format matched",
        )
        exec_res = ExecutionResult(
            experiment_id="EXP-001",
            status="CONFIRMED",
            evidence=["CTF{test}"],
            observed="CTF{test} present",
        )

        updated = self.ledger.record_result(exp.experiment_id, eval_res, exec_res)
        self.assertEqual(updated.outcome, "confirmed")
        self.assertIn("CTF{test}", updated.actual_evidence)

        # Verify get and recent
        fetched = self.ledger.get("EXP-001")
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.outcome, "confirmed")

        recent_exps = self.ledger.recent(3)
        self.assertEqual(len(recent_exps), 1)
        self.assertEqual(recent_exps[0].outcome, "confirmed")

    def test_ledger_malformed_line_resilience(self):
        # Create one valid experiment
        self.ledger.create(hypothesis_id="H1", intent="Valid experiment 1")

        # Inject corrupt/malformed lines into experiments.jsonl
        with open(self.ledger.ledger_file, "a", encoding="utf-8") as f:
            f.write("CORRUPT JSON LINE {{{{ not valid json\n")
            f.write('{"missing_id": true}\n')
            f.write("\n\n")

        # Create second valid experiment
        self.ledger.create(hypothesis_id="H2", intent="Valid experiment 2")

        # Reader must not crash, should return both valid experiments
        exps = self.ledger.list_all()
        self.assertEqual(len(exps), 2)
        self.assertEqual(exps[0].hypothesis_id, "H1")
        self.assertEqual(exps[1].hypothesis_id, "H2")


class TestEvidenceEvaluator(unittest.TestCase):
    """Unit tests for deterministic EvidenceEvaluator."""

    def test_evaluator_expected_evidence_observed_confirmed(self):
        exp = Experiment(
            experiment_id="EXP-001",
            hypothesis_id="H1",
            intent="Check PIE protection",
            expected_evidence=["PIE enabled"],
        )
        exec_res = ExecutionResult(
            experiment_id="EXP-001",
            status="CONFIRMED",
            evidence=["PIE enabled"],
            stdout_tail="RELRO: Full RELRO\nStack: Canary found\nPIE: PIE enabled\n",
        )
        evaluation = EvidenceEvaluator.evaluate(exp, exec_res)
        self.assertEqual(evaluation.outcome, "confirmed")
        self.assertIn("PIE enabled", evaluation.supporting_evidence)

    def test_evaluator_explicit_contradiction_rejected(self):
        exp = Experiment(
            experiment_id="EXP-001",
            hypothesis_id="H1",
            intent="Check whether binary has stack canary",
            expected_evidence=["Canary found"],
            contradicting_evidence=["No canary found"],
        )
        exec_res = ExecutionResult(
            experiment_id="EXP-001",
            status="CONFIRMED",
            return_code=0,
            evidence=["No canary found"],
            stdout_tail="RELRO: Partial RELRO\nStack: No canary found\nNX: NX enabled\n",
        )
        evaluation = EvidenceEvaluator.evaluate(exp, exec_res)
        self.assertEqual(evaluation.outcome, "rejected")
        self.assertTrue(len(evaluation.contradicting_evidence) > 0)

    def test_evaluator_timeout_is_inconclusive_not_rejected(self):
        # CRITICAL INVARIANT: A timeout must NEVER reject a hypothesis
        exp = Experiment(
            experiment_id="EXP-002",
            hypothesis_id="H1",
            intent="Bruteforce PIN with solver",
            expected_evidence=["PIN found: 1337"],
        )
        exec_res = ExecutionResult(
            experiment_id="EXP-002",
            status="ERROR",
            return_code=124,
            observed="Command timed out after 60s",
            stderr_tail="Timeout expired",
        )
        evaluation = EvidenceEvaluator.evaluate(exp, exec_res)
        self.assertEqual(evaluation.outcome, "inconclusive")
        self.assertNotEqual(evaluation.outcome, "rejected")

    def test_evaluator_policy_rejection_is_inconclusive_not_rejected(self):
        exp = Experiment(
            experiment_id="EXP-003",
            hypothesis_id="H1",
            intent="Run disallowed network command",
            expected_evidence=["Connection established"],
        )
        exec_res = ExecutionResult(
            experiment_id="EXP-003",
            status="ERROR",
            return_code=1,
            observed="ActionPolicy validation failed: Policy violation: disallowed tool",
        )
        evaluation = EvidenceEvaluator.evaluate(exp, exec_res)
        self.assertEqual(evaluation.outcome, "inconclusive")
        self.assertNotEqual(evaluation.outcome, "rejected")

    def test_evaluator_flag_candidate_is_flag_found(self):
        exp = Experiment(
            experiment_id="EXP-004",
            hypothesis_id="H1",
            intent="Execute solver script",
            expected_evidence=["Flag output"],
        )
        exec_res = ExecutionResult(
            experiment_id="EXP-004",
            status="FLAG_FOUND",
            flag_candidates=["CTF{solver_intelligence_v3_success}"],
            evidence=["CTF{solver_intelligence_v3_success}"],
        )
        evaluation = EvidenceEvaluator.evaluate(exp, exec_res)
        self.assertEqual(evaluation.outcome, "flag_found")
        self.assertIn("CTF{solver_intelligence_v3_success}", evaluation.supporting_evidence)


class TestDeterministicToyChallengeScenarios(unittest.TestCase):
    """
    End-to-end toy challenge scenarios (Section 15 of prompt):
      - No ChatGPT / Oracle
      - No Docker daemon
      - No network
      - Deterministic file and execution evidence
    """

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.temp_dir.name) / "work"
        self.input_dir = Path(self.temp_dir.name) / "input"
        self.advisor_dir = self.work_dir / ".advisor"
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.input_dir.mkdir(parents=True, exist_ok=True)
        self.advisor_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_toy_scenario_1_marker_present_confirmed(self):
        """
        Scenario 1:
        H1: 'input file contains marker SECRET42'
        Experiment 1: read_file input:challenge.txt expected evidence: 'SECRET42'
        Input contains marker.
        Expected: outcome = confirmed, H1 status = confirmed, ledger & DiscoveryTree updated.
        """
        # Create target file with marker
        chall_file = self.input_dir / "challenge.txt"
        chall_file.write_text("Header: sample\nTarget: SECRET42\nFooter: done\n", encoding="utf-8")

        # Initialize manager and ledger
        hypo = Hypothesis(id="H1", statement="input file contains marker SECRET42")
        hypo_mgr = HypothesisManager([hypo])
        ledger = ExperimentLedger(self.advisor_dir)

        action = ExecutionAction(kind="read_file", path="input:challenge.txt", timeout=10)
        exp = ledger.create(
            hypothesis_id="H1",
            intent="Read challenge.txt to verify SECRET42 marker",
            actions=[action],
            expected_evidence=["SECRET42"],
        )

        # Safe execution through RestrictedLocalExecutor
        executor = RestrictedLocalExecutor()
        challenge_context = {"work_dir": self.work_dir, "input_dir": self.input_dir, "iteration": 1}
        guidance = AdvisorGuidance(is_structured=True, execution_plan=[action])
        exec_res = executor.execute(challenge_context, guidance)

        # Evaluate evidence deterministically
        evaluation = EvidenceEvaluator.evaluate(exp, exec_res)
        self.assertEqual(evaluation.outcome, "confirmed")
        self.assertIn("SECRET42", evaluation.supporting_evidence)

        # Update ledger and hypothesis manager
        ledger.record_result(exp.experiment_id, evaluation, exec_res)
        updated_hypo = hypo_mgr.apply_evaluation("H1", evaluation)
        self.assertEqual(updated_hypo.status, "confirmed")

        # Verify ledger persistence
        saved_exp = ledger.get(exp.experiment_id)
        self.assertEqual(saved_exp.outcome, "confirmed")
        self.assertIn("SECRET42", saved_exp.actual_evidence)

    def test_toy_scenario_2_marker_absent_rejected(self):
        """
        Scenario 2:
        H2: 'input contains marker ADMIN'
        Input does not contain ADMIN but contains explicit known content.
        Expected: outcome = rejected, H2 status = rejected.
        """
        chall_file = self.input_dir / "challenge.txt"
        chall_file.write_text("User: guest\nRole: user\nAccess: denied\n", encoding="utf-8")

        hypo = Hypothesis(id="H2", statement="input contains marker ADMIN")
        hypo_mgr = HypothesisManager([hypo])
        ledger = ExperimentLedger(self.advisor_dir)

        action = ExecutionAction(kind="read_file", path="input:challenge.txt", timeout=10)
        exp = ledger.create(
            hypothesis_id="H2",
            intent="Read challenge.txt to verify ADMIN marker",
            actions=[action],
            expected_evidence=["ADMIN"],
        )

        executor = RestrictedLocalExecutor()
        challenge_context = {"work_dir": self.work_dir, "input_dir": self.input_dir, "iteration": 1}
        guidance = AdvisorGuidance(is_structured=True, execution_plan=[action])
        exec_res = executor.execute(challenge_context, guidance)

        evaluation = EvidenceEvaluator.evaluate(exp, exec_res)
        self.assertEqual(evaluation.outcome, "rejected")

        updated_hypo = hypo_mgr.apply_evaluation("H2", evaluation)
        self.assertEqual(updated_hypo.status, "rejected")
        self.assertEqual(updated_hypo.failure_count, 1)

    def test_toy_scenario_3_execution_timeout_inconclusive_not_rejected(self):
        """
        Scenario 3:
        Execution fails or times out.
        Expected: outcome = inconclusive, NOT rejected.
        """
        hypo = Hypothesis(id="H3", statement="Exploit server buffer overflow")
        hypo_mgr = HypothesisManager([hypo])
        ledger = ExperimentLedger(self.advisor_dir)

        exp = ledger.create(
            hypothesis_id="H3",
            intent="Run long brute force solver",
            expected_evidence=["Password found"],
        )

        # Simulated timeout execution result
        exec_res = ExecutionResult(
            experiment_id=exp.experiment_id,
            status="ERROR",
            return_code=124,
            observed="Command timed out after 30s",
        )

        evaluation = EvidenceEvaluator.evaluate(exp, exec_res)
        self.assertEqual(evaluation.outcome, "inconclusive")
        self.assertNotEqual(evaluation.outcome, "rejected")

        updated_hypo = hypo_mgr.apply_evaluation("H3", evaluation)
        self.assertEqual(updated_hypo.status, "inconclusive")
        self.assertNotEqual(updated_hypo.status, "rejected")


class TestStructuredGuidanceToHypothesisLoop(unittest.TestCase):
    """Integration tests: Guidance -> Experiment -> ExecutionResult -> Evaluation -> Hypothesis."""

    def test_guidance_parser_extracts_experiment_and_executes(self):
        advisor_json = """```json
{
  "hypothesis_id": "H1",
  "intent": "Check binary architecture and protections",
  "expected_evidence": ["ELF 64-bit"],
  "execution_plan": [
    {
      "kind": "read_file",
      "path": "input:sample.txt",
      "timeout": 10
    }
  ]
}
```"""
        guidance = GuidanceParser.parse(advisor_json)
        self.assertTrue(guidance.is_structured)
        self.assertEqual(len(guidance.experiments), 1)
        exp = guidance.experiments[0]
        self.assertEqual(exp.hypothesis_id, "H1")
        self.assertIn("ELF 64-bit", exp.expected_evidence)
        self.assertEqual(len(guidance.execution_plan), 1)
        self.assertEqual(guidance.execution_plan[0].kind, "read_file")


if __name__ == "__main__":
    unittest.main()
