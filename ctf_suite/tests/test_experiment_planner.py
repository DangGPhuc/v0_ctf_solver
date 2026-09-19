import json
from pathlib import Path
import tempfile
import unittest

from ctf_core.advisor.guidance_parser import GuidanceParser
from ctf_core.experiments import (
    CandidateEvaluation,
    ExecutionAction,
    Experiment,
    ExperimentCandidate,
    ExperimentEvaluation,
    ExperimentLedger,
    ExperimentPlanner,
    Hypothesis,
    HypothesisManager,
    SelectionResult,
    SolverProgressTracker,
    compute_experiment_signature,
    normalize_evidence_key,
)
from ctf_core.models import AdvisorGuidance, ExecutionResult


class TestExperimentPlanner(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.advisor_dir = Path(self.temp_dir.name) / ".advisor"
        self.advisor_dir.mkdir(parents=True, exist_ok=True)
        self.ledger = ExperimentLedger(self.advisor_dir)
        self.progress_tracker = SolverProgressTracker(self.advisor_dir)

        self.h1 = Hypothesis(id="H1", statement="Binary has stack buffer overflow in vuln()", status="active")
        self.h2 = Hypothesis(id="H2", statement="Binary has format string bug in report()", status="proposed")
        self.h3 = Hypothesis(id="H3", statement="Binary uses weak PRNG", status="rejected")
        self.hypo_mgr = HypothesisManager(
            hypotheses=[self.h1, self.h2, self.h3],
            max_consecutive_failures=2,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_candidate_parsing_multiple_and_single_backward_compat(self):
        # 1. Multiple candidates
        multi_json = """```json
        {
            "assessment": "Investigate binary",
            "hypotheses": [
                {"id": "H1", "statement": "Stack overflow"},
                {"id": "H2", "statement": "Format string"}
            ],
            "experiment_candidates": [
                {
                    "hypothesis_id": "H1",
                    "intent": "Check protections",
                    "expected_evidence": ["No canary found"],
                    "contradicting_evidence": ["Canary found"],
                    "execution_plan": [
                        {"kind": "analysis_tool", "tool": "checksec", "argv": ["checksec", "--file=input:vuln"]}
                    ],
                    "estimated_cost_class": "low"
                },
                {
                    "hypothesis_id": "H2",
                    "intent": "Inspect format strings",
                    "expected_evidence": ["%p leak"],
                    "execution_plan": [
                        {"kind": "read_file", "path": "input:target.txt"}
                    ],
                    "estimated_cost_class": "medium"
                }
            ]
        }
        ```"""
        g_multi = GuidanceParser.parse(multi_json)
        self.assertTrue(g_multi.is_structured)
        self.assertEqual(len(g_multi.experiment_candidates), 2)
        self.assertEqual(g_multi.experiment_candidates[0].hypothesis_id, "H1")
        self.assertEqual(g_multi.experiment_candidates[1].hypothesis_id, "H2")
        self.assertIsNotNone(g_multi.experiment)
        self.assertEqual(g_multi.experiment.hypothesis_id, "H1")

        # 2. Single experiment backward compatibility
        single_json = """```json
        {
            "assessment": "Single experiment",
            "hypotheses": [{"id": "H1", "statement": "Stack overflow"}],
            "experiment": {
                "experiment_id": "EXP-999",
                "hypothesis_id": "H1",
                "intent": "Single test",
                "expected_evidence": ["Canary found"],
                "execution_plan": [
                    {"kind": "read_file", "path": "input:target.txt"}
                ]
            }
        }
        ```"""
        g_single = GuidanceParser.parse(single_json)
        self.assertTrue(g_single.is_structured)
        self.assertIsNotNone(g_single.experiment)
        self.assertEqual(len(g_single.experiment_candidates), 1)
        self.assertEqual(g_single.experiment_candidates[0].hypothesis_id, "H1")
        self.assertEqual(g_single.experiment_candidates[0].intent, "Single test")

    def test_candidate_canonical_ownership(self):
        cand = ExperimentCandidate(
            hypothesis_id="H1",
            intent="Run inspection",
            execution_plan=[ExecutionAction(kind="read_file", path="input:target.txt")],
            expected_evidence=["marker"],
        )
        # Candidate has no EXP-xxx
        self.assertFalse(hasattr(cand, "experiment_id") and cand.experiment_id is not None)

        planner = ExperimentPlanner()
        sel = planner.select_candidate([cand], self.hypo_mgr, self.ledger, self.progress_tracker)
        self.assertIsNotNone(sel.selected)

        # Only ledger assigns canonical EXP-xxx
        exp = self.ledger.create(
            hypothesis_id=sel.selected.hypothesis_id,
            intent=sel.selected.intent,
            actions=sel.selected.execution_plan,
            expected_evidence=sel.selected.expected_evidence,
        )
        self.assertEqual(exp.experiment_id, "EXP-001")

    def test_planner_selection_lexicographic_ranking(self):
        planner = ExperimentPlanner()

        # Seed known evidence
        self.progress_tracker.record_evidence(["Canary found"])

        cand_known_evidence = ExperimentCandidate(
            hypothesis_id="H1",
            intent="Test known evidence",
            expected_evidence=["Canary found"],
            execution_plan=[ExecutionAction(kind="read_file", path="input:target.txt")],
            estimated_cost_class="low",
        )
        cand_novel_evidence = ExperimentCandidate(
            hypothesis_id="H1",
            intent="Test novel evidence",
            expected_evidence=["SECRET42_MARKER"],
            contradicting_evidence=["CANNOT_EXPLOIT"],
            execution_plan=[ExecutionAction(kind="read_file", path="input:target.txt")],
            estimated_cost_class="low",
        )

        res = planner.select_candidate(
            [cand_known_evidence, cand_novel_evidence],
            self.hypo_mgr,
            self.ledger,
            self.progress_tracker,
        )
        self.assertIsNotNone(res.selected)
        # Novel evidence target with discriminative evidence wins over known evidence
        self.assertEqual(res.selected.intent, "Test novel evidence")
        self.assertIn("SECRET42_MARKER", res.selected.expected_evidence)

    def test_planner_disqualifies_invalid_and_rejected_hypothesis(self):
        planner = ExperimentPlanner()

        # Candidate with disallowed tool
        disallowed_tool_cand = ExperimentCandidate(
            hypothesis_id="H1",
            intent="Run unapproved tool",
            execution_plan=[ExecutionAction(kind="analysis_tool", tool="rm", argv=["rm", "-rf", "/"])],
        )

        # Candidate targeting rejected hypothesis H3
        rejected_hypo_cand = ExperimentCandidate(
            hypothesis_id="H3",
            intent="Test rejected hypo",
            execution_plan=[ExecutionAction(kind="read_file", path="input:target.txt")],
        )

        # Valid candidate targeting proposed hypothesis H2
        valid_h2_cand = ExperimentCandidate(
            hypothesis_id="H2",
            intent="Valid inspection",
            execution_plan=[ExecutionAction(kind="read_file", path="input:target.txt")],
        )

        res = planner.select_candidate(
            [disallowed_tool_cand, rejected_hypo_cand, valid_h2_cand],
            self.hypo_mgr,
            self.ledger,
            self.progress_tracker,
        )
        self.assertIsNotNone(res.selected)
        self.assertEqual(res.selected.hypothesis_id, "H2")

        # Disqualified checks in evaluations
        eval_map = {e.candidate.intent: e for e in res.evaluations}
        self.assertFalse(eval_map["Run unapproved tool"].is_eligible)
        self.assertIn("non_executable", eval_map["Run unapproved tool"].rejection_reason)
        self.assertFalse(eval_map["Test rejected hypo"].is_eligible)
        self.assertIn("hypothesis_rejected", eval_map["Test rejected hypo"].rejection_reason)

    def test_retry_suppression_and_environmental_failure_difference(self):
        planner = ExperimentPlanner()

        cand = ExperimentCandidate(
            hypothesis_id="H1",
            intent="Identical checksec test",
            execution_plan=[ExecutionAction(kind="analysis_tool", tool="checksec", argv=["checksec", "--file=input:vuln"])],
            expected_evidence=["No canary found"],
        )

        # Case 1: First time candidate runs, it is selected
        sel1 = planner.select_candidate([cand], self.hypo_mgr, self.ledger, self.progress_tracker)
        self.assertIsNotNone(sel1.selected)

        # Simulate execution that resulted in REJECTED
        exp = self.ledger.create(
            hypothesis_id=cand.hypothesis_id,
            intent=cand.intent,
            actions=cand.execution_plan,
            expected_evidence=cand.expected_evidence,
        )
        self.ledger.record_result(
            exp.experiment_id,
            ExperimentEvaluation(outcome="rejected", reason="Canary is enabled"),
            ExecutionResult(experiment_id=exp.experiment_id, status="REJECTED"),
        )

        # Case 2: Proposing the exact same candidate again must be suppressed
        sel2 = planner.select_candidate([cand], self.hypo_mgr, self.ledger, self.progress_tracker)
        self.assertIsNone(sel2.selected)
        self.assertIn("retry_suppressed", sel2.evaluations[0].rejection_reason)

        # Case 3: Transient execution failure (outcome == "failed") DOES allow retry
        cand2 = ExperimentCandidate(
            hypothesis_id="H2",
            intent="Transient network check",
            execution_plan=[ExecutionAction(kind="read_file", path="input:target.txt")],
        )
        exp2 = self.ledger.create(
            hypothesis_id=cand2.hypothesis_id,
            intent=cand2.intent,
            actions=cand2.execution_plan,
        )
        # Record outcome as failed (e.g. timeout or execution error)
        exp2_record = self.ledger.get(exp2.experiment_id)
        exp2_record.outcome = "failed"
        self.ledger.append(exp2_record)

        sel3 = planner.select_candidate([cand2], self.hypo_mgr, self.ledger, self.progress_tracker)
        self.assertIsNotNone(sel3.selected)
        self.assertEqual(sel3.selected.hypothesis_id, "H2")

    def test_deterministic_stagnation_detection(self):
        # 3 consecutive rounds with zero new evidence and 3 total experiments
        self.progress_tracker.progress.total_experiments = 3
        self.progress_tracker.progress.rounds_with_zero_new_evidence = 3
        self.assertTrue(self.progress_tracker.is_stagnated(threshold=3))

        # When new evidence is observed, stagnation resets
        self.progress_tracker.record_evidence(["Newly discovered primitive"])
        self.assertEqual(self.progress_tracker.progress.rounds_with_zero_new_evidence, 0)
        self.assertFalse(self.progress_tracker.is_stagnated(threshold=3))


if __name__ == "__main__":
    unittest.main()
