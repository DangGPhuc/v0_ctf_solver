from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from ..models import ExecutionAction, ExperimentCandidate
from ..execution.policy import ALLOWED_ANALYSIS_TOOLS, SUPPORTED_ACTION_KINDS
from .hypothesis_manager import HypothesisManager
from .ledger import ExperimentLedger
from .progress import SolverProgressTracker
from .signatures import compute_experiment_signature


class CandidateEvaluation(BaseModel):
    candidate: ExperimentCandidate
    signature: str
    is_eligible: bool
    rejection_reason: Optional[str] = None
    priority_score: Tuple[int, int, int, int] = (0, 0, 0, 0)
    details: Dict[str, Any] = Field(default_factory=dict)


class SelectionResult(BaseModel):
    selected: Optional[ExperimentCandidate] = None
    reason: str = ""
    evaluations: List[CandidateEvaluation] = Field(default_factory=list)
    stagnation_detected: bool = False


class ExperimentPlanner:
    """
    Deterministic, explainable experiment candidate planner and selector.
    Evaluates candidates proposed by Strategic Advisor against:
      1. Executability & capability boundaries (ActionPolicy allowlist).
      2. Target hypothesis status (active/proposed vs rejected).
      3. Retry suppression (avoids repeated identical failing experiments without state change).
      4. Expected evidence novelty (prefers unseen evidence targets).
      5. Discriminative value (both expected and contradicting evidence).
      6. Cost class tie-breaker (low > medium > high).
    """

    def __init__(
        self,
        capabilities: Optional[Dict[str, Any]] = None,
        stagnation_threshold: int = 3,
    ):
        self.capabilities = capabilities or {}
        self.stagnation_threshold = stagnation_threshold

    def is_executable(self, candidate: ExperimentCandidate) -> Tuple[bool, Optional[str]]:
        """Validates actions against execution policy and tool capability allowlist."""
        actions = candidate.execution_plan
        if not actions:
            return False, "Candidate execution_plan is empty."

        for idx, act in enumerate(actions, start=1):
            if act.kind not in SUPPORTED_ACTION_KINDS:
                return False, f"Action {idx} has unsupported kind '{act.kind}'."
            if act.kind == "analysis_tool":
                tool_name = act.tool or (act.argv[0] if act.argv else None)
                if not tool_name or tool_name not in ALLOWED_ANALYSIS_TOOLS:
                    return False, f"Action {idx} references disallowed analysis tool '{tool_name}'."
        return True, None

    def select_candidate(
        self,
        candidates: List[ExperimentCandidate],
        hypothesis_manager: HypothesisManager,
        ledger: ExperimentLedger,
        progress_tracker: SolverProgressTracker,
    ) -> SelectionResult:
        """
        Deterministically evaluates all candidates and selects the single most promising one.
        """
        if not candidates:
            return SelectionResult(
                selected=None,
                reason="No experiment candidates proposed by Advisor.",
                stagnation_detected=progress_tracker.is_stagnated(self.stagnation_threshold),
            )

        evaluations: List[CandidateEvaluation] = []
        recent_ledger_experiments = ledger.list_all()

        for cand in candidates:
            sig = compute_experiment_signature(cand)
            details: Dict[str, Any] = {"signature": sig}

            # 1. Executability check
            ok, exec_err = self.is_executable(cand)
            if not ok:
                evaluations.append(CandidateEvaluation(
                    candidate=cand,
                    signature=sig,
                    is_eligible=False,
                    rejection_reason=f"non_executable: {exec_err}",
                    details=details,
                ))
                continue

            # 2. Hypothesis state check
            hypo = hypothesis_manager.get(cand.hypothesis_id)
            if not hypo:
                # Unknown hypothesis
                evaluations.append(CandidateEvaluation(
                    candidate=cand,
                    signature=sig,
                    is_eligible=False,
                    rejection_reason=f"unknown_hypothesis: '{cand.hypothesis_id}' not found in HypothesisManager.",
                    details=details,
                ))
                continue

            if hypo.status == "rejected":
                evaluations.append(CandidateEvaluation(
                    candidate=cand,
                    signature=sig,
                    is_eligible=False,
                    rejection_reason=f"hypothesis_rejected: Target hypothesis '{cand.hypothesis_id}' is already rejected.",
                    details=details,
                ))
                continue

            # 3. Retry suppression check
            prior_runs = [
                e for e in recent_ledger_experiments
                if compute_experiment_signature(e) == sig
            ]
            suppressed = False
            suppress_reason = ""
            if prior_runs:
                last_run = prior_runs[-1]
                if last_run.outcome == "rejected":
                    suppressed = True
                    suppress_reason = "retry_suppressed: Identical experiment was previously REJECTED."
                elif last_run.outcome == "inconclusive":
                    # If inconclusive, check if state has progressed since last run
                    # If no new evidence was observed since that run, suppress retry
                    if progress_tracker.progress.rounds_with_zero_new_evidence > 0:
                        suppressed = True
                        suppress_reason = "retry_suppressed: Identical experiment yielded INCONCLUSIVE with zero new evidence since."
                # Note: If last_run.outcome == "failed" (transient error / timeout), retry is allowed.

            if suppressed:
                progress_tracker.record_suppression()
                evaluations.append(CandidateEvaluation(
                    candidate=cand,
                    signature=sig,
                    is_eligible=False,
                    rejection_reason=suppress_reason,
                    details=details,
                ))
                continue

            # 4. Score calculation for ranking
            # Dimension A: Hypothesis preference: active (3) > proposed (2) > confirmed (1)
            hypo_score = 3 if hypo.status == "active" else (2 if hypo.status == "proposed" else 1)

            # Dimension B: Evidence novelty: how many expected evidence targets are currently unknown?
            novel_count = 0
            for ev in cand.expected_evidence:
                if not progress_tracker.is_known_evidence(ev):
                    novel_count += 1

            # Dimension C: Discriminative power: has both expected and contradicting evidence
            discrim_score = 1 if (cand.expected_evidence and cand.contradicting_evidence) else 0

            # Dimension D: Cost tie-breaker: low (3) > medium (2) > high (1)
            cost_map = {"low": 3, "medium": 2, "high": 1}
            cost_score = cost_map.get(cand.estimated_cost_class.lower(), 2)

            score_tuple = (hypo_score, novel_count, discrim_score, cost_score)
            details["hypo_score"] = hypo_score
            details["novel_count"] = novel_count
            details["discrim_score"] = discrim_score
            details["cost_score"] = cost_score

            evaluations.append(CandidateEvaluation(
                candidate=cand,
                signature=sig,
                is_eligible=True,
                priority_score=score_tuple,
                details=details,
            ))

        eligible = [e for e in evaluations if e.is_eligible]
        stagnation = progress_tracker.is_stagnated(self.stagnation_threshold)

        if not eligible:
            return SelectionResult(
                selected=None,
                reason="All proposed candidates were rejected or suppressed by Planner policy.",
                evaluations=evaluations,
                stagnation_detected=stagnation,
            )

        # Lexicographical sort by priority_score descending
        eligible.sort(key=lambda e: e.priority_score, reverse=True)
        winner = eligible[0]

        reason = (
            f"Selected candidate for hypothesis '{winner.candidate.hypothesis_id}' "
            f"(hypo_rank={winner.priority_score[0]}, novel_evidence={winner.priority_score[1]}, "
            f"discriminative={winner.priority_score[2]}, cost_rank={winner.priority_score[3]})."
        )

        return SelectionResult(
            selected=winner.candidate,
            reason=reason,
            evaluations=evaluations,
            stagnation_detected=stagnation,
        )
