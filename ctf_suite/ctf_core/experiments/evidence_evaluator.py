import re
from typing import List, Optional, Tuple

from ..models import ExecutionResult, Experiment, ExperimentEvaluation


class EvidenceEvaluator:
    """
    Deterministic evidence evaluation engine for solver experiments.

    Boundary Invariants:
      - EvidenceEvaluator DOES NOT call any LLM or external network service.
      - EvidenceEvaluator DOES NOT execute tools or commands.
      - Evaluation is strictly deterministic based on ExecutionResult and Experiment claims.
      - Execution errors/timeouts lead to INCONCLUSIVE, NEVER to REJECTED.
    """

    KNOWN_CONTRADICTIONS = [
        (r"canary\s+found", r"no\s+canary\s+found"),
        (r"pie\s+enabled", r"no\s+pie"),
        (r"nx\s+enabled", r"nx\s+disabled"),
        (r"fortify\s+enabled", r"fortify\s+disabled"),
        (r"relro\s+full", r"no\s+relro|partial\s+relro"),
    ]

    @classmethod
    def evaluate(
        cls,
        experiment: Experiment,
        execution_result: ExecutionResult,
    ) -> ExperimentEvaluation:
        """
        Deterministically evaluates whether the observed execution outcome
        confirms, rejects, or is inconclusive for the experiment's hypothesis.
        """
        # 1. Flag Candidate Captured -> Always FLAG_FOUND
        if execution_result.flag_candidates or execution_result.status == "FLAG_FOUND":
            flags = execution_result.flag_candidates or execution_result.evidence
            return ExperimentEvaluation(
                outcome="flag_found",
                supporting_evidence=flags,
                reason=f"Flag candidate(s) discovered: {', '.join(flags)}",
            )

        # 2. Execution Error / Timeout / Tool Missing / Policy Violation -> INCONCLUSIVE
        # CRITICAL INVARIANT: A broken tool, timeout, or non-zero exit does not prove a hypothesis false!
        if cls._is_execution_failure(execution_result):
            fail_reason = (
                execution_result.observed
                or execution_result.stderr_tail
                or f"Execution returned code {execution_result.return_code} with status {execution_result.status}"
            )
            return ExperimentEvaluation(
                outcome="inconclusive",
                reason=f"Execution error/timeout prevents hypothesis validation: {fail_reason[:150]}",
            )

        # Gather all observed textual surfaces
        observed_corpus = cls._gather_observed_corpus(execution_result)

        # 3. Check for Explicit Contradictory Evidence -> REJECTED
        matching_contradictions = []
        for contradiction in experiment.contradicting_evidence:
            if cls._matches(contradiction, observed_corpus):
                matching_contradictions.append(contradiction)

        # Check known binary/domain contradiction pairs
        for positive_pat, negative_pat in cls.KNOWN_CONTRADICTIONS:
            for expected in experiment.expected_evidence:
                if re.search(positive_pat, expected, re.IGNORECASE):
                    if re.search(negative_pat, observed_corpus, re.IGNORECASE):
                        matching_contradictions.append(f"Explicit contradiction: observed '{negative_pat}' for expected '{expected}'")

        if matching_contradictions:
            return ExperimentEvaluation(
                outcome="rejected",
                contradicting_evidence=matching_contradictions,
                reason=f"Explicit contradictory evidence observed: {', '.join(matching_contradictions)}",
            )

        # 4. Check for Positively Observed Expected Evidence -> CONFIRMED
        matching_supported = []
        for expected in experiment.expected_evidence:
            if cls._matches_positive(expected, observed_corpus):
                matching_supported.append(expected)

        if matching_supported:
            return ExperimentEvaluation(
                outcome="confirmed",
                supporting_evidence=matching_supported,
                reason=f"Positively observed expected evidence: {', '.join(matching_supported)}",
            )

        # 5. Exact Content Marker Absence in Clean File Inspection -> REJECTED
        # If the action was an exact inspection (read_file or dump) and succeeded cleanly (return_code 0),
        # but the specific target marker was definitely absent from the complete inspected content:
        if cls._is_definitive_negative_inspection(experiment, execution_result, observed_corpus):
            missing_markers = experiment.expected_evidence or [experiment.intent]
            return ExperimentEvaluation(
                outcome="rejected",
                contradicting_evidence=[f"Inspected content lacks expected: {', '.join(missing_markers)}"],
                reason=f"Target content inspected completely without errors; expected marker(s) absent: {', '.join(missing_markers)}",
            )

        # 6. Succeeded but Insufficient Evidence -> INCONCLUSIVE
        return ExperimentEvaluation(
            outcome="inconclusive",
            reason="Action executed successfully but expected evidence was not definitively observed",
        )

    @classmethod
    def _is_execution_failure(cls, res: ExecutionResult) -> bool:
        if res.status in ["ERROR"]:
            return True
        if res.return_code is not None and res.return_code in [124, 137]:
            return True
        obs_lower = (res.observed or "").lower()
        err_lower = (res.stderr_tail or "").lower()
        if "timed out" in obs_lower or "timed out" in err_lower:
            return True
        if "policy violation" in obs_lower or "policy rejection" in obs_lower:
            return True
        if "command not found" in err_lower or "executable missing" in err_lower or "no such file or directory: 'checksec'" in err_lower:
            return True
        return False

    @classmethod
    def _gather_observed_corpus(cls, res: ExecutionResult) -> str:
        parts = []
        if res.observed:
            parts.append(res.observed)
        if res.evidence:
            parts.extend(res.evidence)
        if res.stdout_tail:
            parts.append(res.stdout_tail)
        if res.stderr_tail:
            parts.append(res.stderr_tail)
        return "\n".join(parts)

    @classmethod
    def _matches_positive(cls, pattern: str, text: str) -> bool:
        if not pattern or not text:
            return False
        # If text explicitly negates pattern right before, e.g. "no canary found"
        neg_regex = rf"(?:no|not|without|disabled|lacks|missing)\s+{re.escape(pattern)}"
        if re.search(neg_regex, text, re.IGNORECASE):
            return False
        return cls._matches(pattern, text)

    @classmethod
    def _matches(cls, pattern: str, text: str) -> bool:
        if not pattern or not text:
            return False
        # Direct case-insensitive substring match
        if pattern.lower() in text.lower():
            return True
        # Try regex if pattern contains regex special chars
        try:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        except Exception:
            pass
        return False

    @classmethod
    def _is_definitive_negative_inspection(
        cls,
        exp: Experiment,
        res: ExecutionResult,
        observed_corpus: str,
    ) -> bool:
        """
        Checks if the experiment was a deterministic inspection (e.g. read_file)
        that completed cleanly with non-empty content, proving the marker is absent.
        """
        if res.return_code != 0 and res.return_code is not None:
            return False
        if not observed_corpus.strip():
            return False

        # Output MUST be complete (not truncated) to prove definitive absence
        if not getattr(res, "output_complete", True) or getattr(res, "stdout_truncated", False):
            return False

        # Strictly read_file only: generic analysis_tool absence is NEVER definitive absence
        actions = exp.actions_to_run
        is_read_file = any(a.kind == "read_file" for a in actions)
        if not is_read_file:
            return False

        if exp.expected_evidence:
            return True

        return False
