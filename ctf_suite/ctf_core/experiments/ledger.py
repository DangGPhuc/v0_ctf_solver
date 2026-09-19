from datetime import datetime
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional

from ..models import (
    ExecutionAction,
    ExecutionResult,
    Experiment,
    ExperimentEvaluation,
)


class ExperimentLedger:
    """
    Canonical challenge-local experiment history writer and reader.
    Backing store: .advisor/experiments.jsonl (append-only JSONL format).

    Invariants:
      - Canonical writer: All experiment outcomes and attempts are recorded here.
      - Resilient: Malformed lines never crash the reader.
      - Challenge-local: Strictly confined to challenge runtime directory.
      - No credentials/secrets persisted.
    """

    def __init__(self, ledger_file_or_advisor_dir: Path):
        p = Path(ledger_file_or_advisor_dir)
        if p.is_dir() or p.name != "experiments.jsonl":
            self.ledger_file = p / "experiments.jsonl"
        else:
            self.ledger_file = p
        self.ledger_file.parent.mkdir(parents=True, exist_ok=True)

    def next_experiment_id(self) -> str:
        """Generates next stable sequential experiment ID (e.g. EXP-001, EXP-002)."""
        existing = self.list_all()
        max_id = 0
        for exp in existing:
            m = re.match(r"^EXP-(\d+)$", exp.experiment_id, re.IGNORECASE)
            if m:
                max_id = max(max_id, int(m.group(1)))
        return f"EXP-{max_id + 1:03d}"

    def create(
        self,
        hypothesis_id: str,
        intent: str,
        actions: Optional[List[ExecutionAction]] = None,
        expected_evidence: Optional[List[str]] = None,
        contradicting_evidence: Optional[List[str]] = None,
        experiment_id: Optional[str] = None,
    ) -> Experiment:
        """Creates and appends a new pending experiment."""
        exp_id = experiment_id or self.next_experiment_id()
        exp = Experiment(
            experiment_id=exp_id,
            hypothesis_id=hypothesis_id,
            intent=intent,
            execution_plan=actions or [],
            expected_evidence=expected_evidence or [],
            contradicting_evidence=contradicting_evidence or [],
            outcome="pending",
            created_at=datetime.now().isoformat(),
        )
        self.append(exp)
        return exp

    def append(self, experiment: Experiment) -> None:
        """Appends an experiment record to the canonical JSONL ledger."""
        entry = self._serialize_entry(experiment)
        with open(self.ledger_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def get(self, experiment_id: str) -> Optional[Experiment]:
        """Retrieves an experiment by ID."""
        for exp in reversed(self.list_all()):
            if exp.experiment_id == experiment_id:
                return exp
        return None

    def list_all(self) -> List[Experiment]:
        """
        Loads all experiments from the ledger, deduplicating by experiment_id
        so the latest updated state wins. Malformed lines are skipped safely.
        """
        if not self.ledger_file.is_file():
            return []

        entries_by_id: Dict[str, Experiment] = {}
        try:
            with open(self.ledger_file, "r", encoding="utf-8") as f:
                for line in f:
                    line_str = line.strip()
                    if not line_str:
                        continue
                    try:
                        raw = json.loads(line_str)
                        exp = self._deserialize_entry(raw)
                        if exp:
                            entries_by_id[exp.experiment_id] = exp
                    except Exception:
                        # Malformed line resilience: skip corrupt lines cleanly
                        continue
        except Exception:
            return []

        return list(entries_by_id.values())

    def list_for_hypothesis(self, hypothesis_id: str) -> List[Experiment]:
        """Returns all experiments targeting a specific hypothesis."""
        return [e for e in self.list_all() if e.hypothesis_id == hypothesis_id]

    def record_result(
        self,
        experiment_id: str,
        evaluation: ExperimentEvaluation,
        execution_result: ExecutionResult,
    ) -> Experiment:
        """
        Records the deterministic evaluation and execution result for an experiment.
        Appends the completed record to the canonical ledger.
        """
        existing = self.get(experiment_id)
        if existing:
            exp = existing.model_copy()
        else:
            exp = Experiment(
                experiment_id=experiment_id,
                hypothesis_id="H1",
                intent="Execute solver action",
            )

        exp.outcome = evaluation.outcome
        exp.reason = evaluation.reason
        exp.completed_at = datetime.now().isoformat()

        # Combine actual evidence observed
        combined_evidence = list(exp.actual_evidence)
        for ev in (execution_result.evidence or []) + evaluation.supporting_evidence + evaluation.contradicting_evidence:
            if ev and ev not in combined_evidence:
                combined_evidence.append(ev)
        exp.actual_evidence = combined_evidence

        self.append(exp)
        return exp

    def recent(self, n: int = 3) -> List[Experiment]:
        """Returns the most recent n experiments."""
        all_exps = self.list_all()
        return all_exps[-n:] if len(all_exps) > n else all_exps

    def _serialize_entry(self, exp: Experiment) -> Dict[str, Any]:
        """
        Produces a backward-compatible dictionary that satisfies both
        Experiment model and existing tools reading experiments.jsonl
        (e.g. PromptCompiler and DiscoveryTree).
        """
        action_names = [a.kind for a in exp.actions_to_run]
        actions_str = ", ".join(action_names) if action_names else "run_solver"
        observed_str = "; ".join(exp.actual_evidence) if exp.actual_evidence else exp.reason

        return {
            "id": exp.experiment_id,
            "experiment_id": exp.experiment_id,
            "timestamp": exp.completed_at or exp.created_at,
            "hypothesis": exp.hypothesis_id,
            "hypothesis_id": exp.hypothesis_id,
            "intent": exp.intent,
            "actions": actions_str,
            "actions_detail": [a.model_dump() for a in exp.actions_to_run],
            "expected_evidence": exp.expected_evidence,
            "contradicting_evidence": exp.contradicting_evidence,
            "actual_evidence": exp.actual_evidence,
            "observed": observed_str,
            "status": exp.outcome.upper(),
            "outcome": exp.outcome,
            "reason": exp.reason,
            "diff": "",
            "evidence": "; ".join(exp.actual_evidence),
        }

    def _deserialize_entry(self, raw: Dict[str, Any]) -> Optional[Experiment]:
        """Reconstructs Experiment from raw dictionary safely."""
        exp_id = raw.get("experiment_id") or raw.get("id")
        if not exp_id:
            return None

        hypo_id = raw.get("hypothesis_id") or raw.get("hypothesis") or "H1"
        intent = raw.get("intent") or raw.get("actions") or "Experiment action"

        # Map legacy status strings to outcome literals
        status_raw = str(raw.get("outcome") or raw.get("status") or "pending").lower()
        if status_raw in ["confirmed", "rejected", "inconclusive", "failed", "flag_found", "pending"]:
            outcome = status_raw
        elif status_raw in ["error", "unknown"]:
            outcome = "inconclusive"
        else:
            outcome = "pending"

        actions: List[ExecutionAction] = []
        if "actions_detail" in raw and isinstance(raw["actions_detail"], list):
            for a_raw in raw["actions_detail"]:
                try:
                    actions.append(ExecutionAction.model_validate(a_raw))
                except Exception:
                    pass

        expected = raw.get("expected_evidence")
        if isinstance(expected, str):
            expected_list = [expected] if expected else []
        elif isinstance(expected, list):
            expected_list = [str(x) for x in expected]
        else:
            expected_list = []

        contradicting = raw.get("contradicting_evidence")
        if isinstance(contradicting, str):
            contradicting_list = [contradicting] if contradicting else []
        elif isinstance(contradicting, list):
            contradicting_list = [str(x) for x in contradicting]
        else:
            contradicting_list = []

        actual = raw.get("actual_evidence")
        if isinstance(actual, str):
            actual_list = [actual] if actual else []
        elif isinstance(actual, list):
            actual_list = [str(x) for x in actual]
        else:
            actual_list = []

        return Experiment(
            experiment_id=str(exp_id),
            hypothesis_id=str(hypo_id),
            intent=str(intent),
            execution_plan=actions,
            expected_evidence=expected_list,
            contradicting_evidence=contradicting_list,
            actual_evidence=actual_list,
            outcome=outcome,
            reason=str(raw.get("reason") or raw.get("observed") or ""),
            created_at=str(raw.get("timestamp") or datetime.now().isoformat()),
            completed_at=str(raw.get("timestamp")) if outcome != "pending" else None,
        )
