import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock

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
    ExperimentProposal,
    Hypothesis,
    HypothesisManager,
    HypothesisRecord,
    UnknownExperimentError,
    UnknownHypothesisError,
)
from ctf_core.models import AdvisorGuidance, AdvisorResult, Challenge
from ctf_core.runtime.manager import RuntimeManager
from ctf_core.execution.restricted_executor import RestrictedLocalExecutor
from ctf_core.services.advisor_service import AdvisorService
from ctf_core.services.orchestrator import ChallengeOrchestrator


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
        self.assertFalse(mgr.recommend_pivot())  # Confirmed hypothesis does NOT force pivot; experiments build on established facts

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


class TestPhase1ProductionClosure(unittest.TestCase):
    """
    Phase 1 Production-Closure Regression Suite (Sections 21-28):
    Verifies canonical experiment ownership, production closed-loop binding,
    hypothesis attribution invariants, pivot semantics, inconclusive budget,
    and absence evidence tightening.
    """

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.runtime_manager = RuntimeManager(base_dir=self.root / ".runtime")
        self.event_id = "test_event"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_production_closed_loop_regression(self):
        """
        Required Test 21 & 22: Full Production Integration Path
        Advisor structured response -> GuidanceParser -> AdvisorService canonical experiment creation
        -> challenge_context['experiment_id'] -> RestrictedLocalExecutor -> ExecutionRunner
        -> ExecutionResult -> AdvisorService.report_execution -> ExperimentLedger -> HypothesisManager.
        No ChatGPT, no Docker, mock ONLY the Advisor provider.
        """
        cid = "chall_p1_prod"
        chall = Challenge(id=cid, name="ProdClosureToy", category="Rev")
        cpath = self.runtime_manager.materialize_challenge(self.event_id, chall)
        work_dir = cpath / "work"
        input_dir = cpath / "input"
        (input_dir / "target.txt").write_text("Binary analysis: Canary found in checksec\n", encoding="utf-8")

        adv_service = AdvisorService(
            workspace_dir=self.root,
            runtime_manager=self.runtime_manager,
            event_id=self.event_id,
        )
        adv_service.init_challenge_advisor(cid, force=True)

        standard_advisor_response = """```json
{
  "assessment": "Check binary protections for stack canary",
  "hypotheses": [
    {
      "id": "H1",
      "statement": "Binary has stack canary protection enabled",
      "confidence": 0.85,
      "rationale": "Compiled with default GCC stack protection"
    }
  ],
  "experiment": {
    "hypothesis_id": "H1",
    "intent": "Read target.txt to inspect checksec output",
    "expected_evidence": [
      "Canary found"
    ],
    "contradicting_evidence": [
      "No canary found"
    ],
    "execution_plan": [
      {
        "kind": "read_file",
        "path": "input:target.txt",
        "timeout": 10
      }
    ]
  },
  "stop_conditions": [
    "Protections verified"
  ]
}
```"""
        mock_adv_res = AdvisorResult(
            status="READY",
            provider="chatgpt-web",
            session_id="session_mock_prod",
            raw_response=standard_advisor_response,
        )

        with patch.object(adv_service.advisor_provider, "consult", return_value=mock_adv_res):
            consult_res = adv_service.consult(cid)

        self.assertEqual(consult_res["status"], "READY")
        canonical_exp_id = consult_res.get("active_experiment_id")
        self.assertEqual(canonical_exp_id, "EXP-001")

        # Invariant 8: Canonical pending experiment MUST exist in ledger BEFORE execution
        advisor_dir = cpath / ".advisor"
        ledger = ExperimentLedger(advisor_dir)
        pre_exec_exp = ledger.get("EXP-001")
        self.assertIsNotNone(pre_exec_exp)
        self.assertEqual(pre_exec_exp.hypothesis_id, "H1")
        self.assertEqual(pre_exec_exp.outcome, "pending")

        # Invariant 9 & 10: Production executor context binds canonical experiment_id
        challenge_context = {
            "challenge_id": cid,
            "name": "ProdClosureToy",
            "category": "Rev",
            "work_dir": work_dir,
            "input_dir": input_dir,
            "iteration": 1,
            "experiment_id": canonical_exp_id,
        }

        executor = RestrictedLocalExecutor()
        exec_result = executor.execute(challenge_context, consult_res["guidance"])

        # Verify ExecutionResult carries exact canonical persisted ID
        self.assertEqual(exec_result.experiment_id, "EXP-001")

        # Report execution back through production AdvisorService.report_execution
        report_out = adv_service.report_execution(cid, exec_result)
        self.assertEqual(report_out["status"], "CONFIRMED")
        self.assertEqual(report_out["experiment_id"], "EXP-001")

        # Verify ledger updated the same experiment record without synthesizing a second one
        all_exps = ledger.list_all()
        self.assertEqual(len(all_exps), 1)
        post_exec_exp = ledger.get("EXP-001")
        self.assertEqual(post_exec_exp.outcome, "confirmed")
        self.assertIn("Canary found", post_exec_exp.actual_evidence)

        # Verify HypothesisManager updated H1 to confirmed
        hypo_mgr = HypothesisManager.load(advisor_dir / "hypotheses.json")
        h1 = hypo_mgr.get("H1")
        self.assertIsNotNone(h1)
        self.assertEqual(h1.status, "confirmed")
        self.assertEqual(h1.failure_count, 0)

    def test_system_owns_experiment_ids_advisor_cannot_dictate(self):
        """
        Required Test 23: Advisor attempts to supply EXP-999; system canonical ID EXP-001 wins.
        """
        cid = "chall_id_test"
        chall = Challenge(id=cid, name="IDTest", category="Pwn")
        cpath = self.runtime_manager.materialize_challenge(self.event_id, chall)
        adv_service = AdvisorService(workspace_dir=self.root, runtime_manager=self.runtime_manager, event_id=self.event_id)
        adv_service.init_challenge_advisor(cid, force=True)

        rogue_advisor_response = """```json
{
  "assessment": "Rogue experiment ID proposal",
  "hypotheses": [{"id": "H1", "statement": "Test claim"}],
  "experiment": {
    "experiment_id": "EXP-999",
    "hypothesis_id": "H1",
    "intent": "Attempt to hijack system ID",
    "expected_evidence": ["Evidence"],
    "execution_plan": [{"kind": "list_files", "timeout": 5}]
  }
}
```"""
        mock_res = AdvisorResult(status="READY", provider="oracle", raw_response=rogue_advisor_response)
        with patch.object(adv_service.advisor_provider, "consult", return_value=mock_res):
            consult_res = adv_service.consult(cid)

        # System canonical ID EXP-001 must win; EXP-999 must NOT be active_experiment_id
        self.assertEqual(consult_res["active_experiment_id"], "EXP-001")
        ledger = ExperimentLedger(cpath / ".advisor")
        self.assertIsNone(ledger.get("EXP-999"))
        self.assertIsNotNone(ledger.get("EXP-001"))

    def test_h2_experiment_must_not_mutate_h1(self):
        """
        Required Test 24: H1 active, H2 registered. Experiment targets H2.
        Evidence confirms experiment. Expected: H2 -> confirmed, H1 UNCHANGED.
        """
        cid = "chall_h2_test"
        chall = Challenge(id=cid, name="H2Test", category="Web")
        cpath = self.runtime_manager.materialize_challenge(self.event_id, chall)
        advisor_dir = cpath / ".advisor"
        adv_service = AdvisorService(workspace_dir=self.root, runtime_manager=self.runtime_manager, event_id=self.event_id)
        adv_service.init_challenge_advisor(cid, force=True)

        # Register H1 (active) and H2 (proposed)
        hypo_mgr = HypothesisManager.load(advisor_dir / "hypotheses.json")
        hypo_mgr.register([
            Hypothesis(id="H1", statement="Vulnerability in SQL query", status="proposed"),
            Hypothesis(id="H2", statement="Vulnerability in SSRF endpoint", status="proposed"),
        ])
        hypo_mgr.activate("H1")
        hypo_mgr.save(advisor_dir / "hypotheses.json")

        # Update state with active H1
        state_file = advisor_dir / "state.json"
        state = json.loads(state_file.read_text(encoding="utf-8"))
        state["active_hypothesis_id"] = "H1"
        state["active_hypothesis"] = "Vulnerability in SQL query"
        state_file.write_text(json.dumps(state), encoding="utf-8")

        # Create experiment explicitly targeting H2
        ledger = ExperimentLedger(advisor_dir)
        exp_h2 = ledger.create(
            hypothesis_id="H2",
            intent="Test SSRF loopback endpoint",
            expected_evidence=["127.0.0.1 root access"],
        )

        # Execute result confirming H2
        exec_res = ExecutionResult(
            experiment_id=exp_h2.experiment_id,
            status="CONFIRMED",
            evidence=["127.0.0.1 root access"],
            observed="SSRF loopback returned root metadata",
        )

        adv_service.report_execution(cid, exec_res)

        # Invariant: ONLY H2 must transition; H1 must remain unchanged
        hypo_mgr_post = HypothesisManager.load(advisor_dir / "hypotheses.json")
        h1_post = hypo_mgr_post.get("H1")
        h2_post = hypo_mgr_post.get("H2")

        self.assertEqual(h2_post.status, "confirmed")
        self.assertEqual(h1_post.status, "active")
        self.assertEqual(h1_post.failure_count, 0)
        self.assertEqual(h1_post.attempts, 0)

    def test_unknown_experiment_fails_closed_no_synthetic_h1(self):
        """
        Required Test 25: ExecutionResult references unknown EXP-999.
        Expected: raises UnknownExperimentError, NO hypothesis state transition,
        NO synthetic H1 experiment created in ledger.
        """
        cid = "chall_unknown_exp"
        chall = Challenge(id=cid, name="UnknownExpTest", category="Crypto")
        cpath = self.runtime_manager.materialize_challenge(self.event_id, chall)
        advisor_dir = cpath / ".advisor"
        adv_service = AdvisorService(workspace_dir=self.root, runtime_manager=self.runtime_manager, event_id=self.event_id)
        adv_service.init_challenge_advisor(cid, force=True)

        hypo_mgr = HypothesisManager.load(advisor_dir / "hypotheses.json")
        hypo_mgr.register([Hypothesis(id="H1", statement="Original H1 statement", status="proposed")])
        hypo_mgr.activate("H1")
        hypo_mgr.save(advisor_dir / "hypotheses.json")

        unknown_result = ExecutionResult(
            experiment_id="EXP-999",
            status="CONFIRMED",
            evidence=["Some fabricated evidence"],
            observed="Fabricated observation",
        )

        with self.assertRaises(UnknownExperimentError):
            adv_service.report_execution(cid, unknown_result)

        # Verify NO synthetic experiment was written to ledger
        ledger = ExperimentLedger(advisor_dir)
        self.assertEqual(len(ledger.list_all()), 0)
        self.assertIsNone(ledger.get("EXP-999"))

        # Verify H1 was NOT mutated
        hypo_mgr_post = HypothesisManager.load(advisor_dir / "hypotheses.json")
        h1 = hypo_mgr_post.get("H1")
        self.assertEqual(h1.status, "active")
        self.assertEqual(h1.attempts, 0)

    def test_confirmed_hypothesis_does_not_force_pivot(self):
        """
        Required Test 26: H1 active evaluation = confirmed.
        Expected: H1.status == confirmed, recommend_pivot() == False.
        """
        h1 = Hypothesis(id="H1", statement="Vulnerable buffer overflow exists", status="proposed")
        mgr = HypothesisManager(hypotheses=[h1], max_consecutive_failures=2)
        eval_confirm = ExperimentEvaluation(
            outcome="confirmed",
            supporting_evidence=["EIP overwrite verified"],
            reason="Controlled crash at offset 120",
        )
        updated = mgr.apply_evaluation("H1", eval_confirm)
        self.assertEqual(updated.status, "confirmed")
        self.assertFalse(mgr.recommend_pivot())

    def test_inconclusive_budget_triggers_pivot_required(self):
        """
        Required Test 27: Budget max_consecutive_failures = 2.
        EXP-001 -> inconclusive: pivot_required == False
        EXP-002 -> inconclusive: pivot_required == True
        Do NOT mark hypothesis rejected merely because experiments were inconclusive.
        """
        cid = "chall_budget_test"
        chall = Challenge(id=cid, name="BudgetTest", category="Pwn")
        cpath = self.runtime_manager.materialize_challenge(self.event_id, chall)
        advisor_dir = cpath / ".advisor"
        adv_service = AdvisorService(workspace_dir=self.root, runtime_manager=self.runtime_manager, event_id=self.event_id)
        adv_service.init_challenge_advisor(cid, force=True)

        hypo_mgr = HypothesisManager.load(advisor_dir / "hypotheses.json")
        hypo_mgr.register([Hypothesis(id="H1", statement="Difficult heap exploit primitive", status="proposed")])
        hypo_mgr.activate("H1")
        hypo_mgr.save(advisor_dir / "hypotheses.json")

        ledger = ExperimentLedger(advisor_dir)
        exp1 = ledger.create(hypothesis_id="H1", intent="Attempt tcache poisoning")
        exp2 = ledger.create(hypothesis_id="H1", intent="Attempt fastbin dup")

        # First inconclusive experiment
        res1 = ExecutionResult(
            experiment_id=exp1.experiment_id,
            status="INCONCLUSIVE",
            observed="Heap layout shifted unexpectedly; inconclusive",
        )
        out1 = adv_service.report_execution(cid, res1)
        self.assertFalse(out1["pivot_required"])

        # Second inconclusive experiment
        res2 = ExecutionResult(
            experiment_id=exp2.experiment_id,
            status="INCONCLUSIVE",
            observed="Double free detected by glibc; inconclusive",
        )
        out2 = adv_service.report_execution(cid, res2)
        self.assertTrue(out2["pivot_required"])
        self.assertTrue(out2["is_stalled"])

        # Verify hypothesis is NOT marked rejected
        hypo_mgr_post = HypothesisManager.load(advisor_dir / "hypotheses.json")
        h1_post = hypo_mgr_post.get("H1")
        self.assertEqual(h1_post.status, "inconclusive")
        self.assertNotEqual(h1_post.status, "rejected")

    def test_absence_semantics_file_marker_vs_analysis_tool(self):
        """
        Required Test 28:
        Case A: read_file expected marker SECRET42, clean read, marker absent -> rejected.
        Case B: analysis_tool expected 'Canary found', tool succeeds, output lacks marker
                and lacks explicit contradiction -> inconclusive.
        Case C: analysis_tool output explicitly contains 'No canary found' -> rejected.
        """
        # Case A: read_file + marker absent
        exp_a = Experiment(
            experiment_id="EXP-001",
            hypothesis_id="H1",
            intent="Read config for SECRET42",
            expected_evidence=["SECRET42"],
            execution_plan=[ExecutionAction(kind="read_file", path="config.txt")],
        )
        res_a = ExecutionResult(
            experiment_id="EXP-001",
            status="INCONCLUSIVE",
            return_code=0,
            stdout_tail="server_name=ctf_app\nport=8080\nenv=production\n",
            observed="Read config file successfully",
        )
        eval_a = EvidenceEvaluator.evaluate(exp_a, res_a)
        self.assertEqual(eval_a.outcome, "rejected")

        # Case B: analysis_tool + missing positive phrase without contradiction -> inconclusive
        exp_b = Experiment(
            experiment_id="EXP-002",
            hypothesis_id="H1",
            intent="Run checksec tool",
            expected_evidence=["Canary found"],
            execution_plan=[ExecutionAction(kind="analysis_tool", tool="checksec", argv=["checksec", "--file=vuln"])],
        )
        res_b = ExecutionResult(
            experiment_id="EXP-002",
            status="INCONCLUSIVE",
            return_code=0,
            stdout_tail="Arch: amd64-64-little\nRELRO: Full RELRO\nNX: NX enabled\n",
            observed="Checksec finished cleanly",
        )
        eval_b = EvidenceEvaluator.evaluate(exp_b, res_b)
        self.assertEqual(eval_b.outcome, "inconclusive")

        # Case C: analysis_tool + explicit contradiction present -> rejected
        exp_c = Experiment(
            experiment_id="EXP-003",
            hypothesis_id="H1",
            intent="Run checksec tool",
            expected_evidence=["Canary found"],
            contradicting_evidence=["No canary found"],
            execution_plan=[ExecutionAction(kind="analysis_tool", tool="checksec", argv=["checksec", "--file=vuln"])],
        )
        res_c = ExecutionResult(
            experiment_id="EXP-003",
            status="INCONCLUSIVE",
            return_code=0,
            stdout_tail="Arch: amd64-64-little\nStack: No canary found\nNX: NX enabled\n",
            observed="Checksec executed cleanly",
        )
        eval_c = EvidenceEvaluator.evaluate(exp_c, res_c)
        self.assertEqual(eval_c.outcome, "rejected")

    def test_orchestrator_invariant_check_fails_on_mismatched_id(self):
        """
        Required Invariant 10: If ExecutionResult.experiment_id does not match
        canonical active_experiment_id, ChallengeOrchestrator must FAIL CLOSED with RuntimeError.
        """
        cid = "chall_mismatch_test"
        chall = Challenge(id=cid, name="MismatchTest", category="Misc")
        self.runtime_manager.materialize_challenge(self.event_id, chall)

        # Mock advisor returning active_experiment_id='EXP-001'
        mock_advisor = MagicMock(spec=AdvisorService)
        mock_guidance = AdvisorGuidance(is_structured=True, execution_plan=[ExecutionAction(kind="list_files")])
        mock_advisor.consult.return_value = {
            "status": "READY",
            "active_experiment_id": "EXP-001",
            "guidance": mock_guidance,
        }

        # Rogue executor returning mismatched experiment_id='EXP-999'
        rogue_executor = MagicMock()
        rogue_executor.execute.return_value = ExecutionResult(
            experiment_id="EXP-999",  # Mismatched ID!
            status="INCONCLUSIVE",
        )

        orchestrator = ChallengeOrchestrator(
            workspace_dir=self.root,
            runtime_manager=self.runtime_manager,
            event_id=self.event_id,
            advisor=mock_advisor,
            executor=rogue_executor,
            max_iterations_per_chall=1,
        )

        chall_info = {"id": cid, "name": "MismatchTest", "category": "Misc"}
        with self.assertRaises(RuntimeError) as ctx:
            orchestrator.execute_challenge_cycle(chall_info)

        self.assertIn("Orchestration invariant violation", str(ctx.exception))
        self.assertIn("EXP-999", str(ctx.exception))
        self.assertIn("EXP-001", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
