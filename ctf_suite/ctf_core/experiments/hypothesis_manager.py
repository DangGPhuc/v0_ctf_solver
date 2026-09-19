import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models import ExperimentEvaluation, Hypothesis, HypothesisRecord


class UnknownHypothesisError(KeyError):
    """Raised when an operation targets an unregistered hypothesis."""
    pass


class HypothesisManager:
    """
    Manages the solver's explicit hypothesis reasoning state and lifecycle.

    Boundary Invariants:
      - HypothesisManager DOES NOT execute tools.
      - HypothesisManager DOES NOT submit flags.
      - HypothesisManager DOES NOT communicate with external CTF platforms.
      - HypothesisManager DOES NOT retrieve knowledge.
      - HypothesisManager ONLY tracks hypothesis reasoning state and transitions.
    """

    def __init__(
        self,
        hypotheses: Optional[List[Hypothesis]] = None,
        max_consecutive_failures: int = 2,
    ):
        self.max_consecutive_failures = max(1, max_consecutive_failures)
        self._hypotheses: Dict[str, Hypothesis] = {}
        self._active_id: Optional[str] = None
        if hypotheses:
            self.register(hypotheses)

    def register(self, hypotheses: List[Hypothesis]) -> List[Hypothesis]:
        """Registers a list of hypotheses without overwriting confirmed/rejected states."""
        registered = []
        for h in hypotheses:
            existing = self._hypotheses.get(h.id)
            if existing is None:
                # New hypothesis
                self._hypotheses[h.id] = h
                registered.append(h)
            else:
                # Preserve verified outcomes from history; only update statement/rationale if still proposed
                if existing.status == "proposed":
                    existing.statement = h.statement
                    existing.rationale = h.rationale
                    existing.confidence = h.confidence
                registered.append(existing)

        # Auto-activate first proposed hypothesis if none currently active
        if not self._active_id and registered:
            for h in registered:
                if h.status in ["proposed", "active"]:
                    self.activate(h.id)
                    break

        return registered

    def activate(self, hypothesis_id: str) -> Optional[Hypothesis]:
        """Activates a specific hypothesis."""
        target = self._hypotheses.get(hypothesis_id)
        if not target:
            return None

        # Deactivate existing active hypothesis if still in active state
        if self._active_id and self._active_id != hypothesis_id:
            curr = self._hypotheses.get(self._active_id)
            if curr and curr.status == "active":
                curr.status = "proposed"

        if target.status == "proposed":
            target.status = "active"

        self._active_id = hypothesis_id
        return target

    def get_active(self) -> Optional[Hypothesis]:
        """Returns the currently active hypothesis."""
        if self._active_id:
            return self._hypotheses.get(self._active_id)
        return None

    def get(self, hypothesis_id: str) -> Optional[Hypothesis]:
        """Returns a hypothesis by ID."""
        return self._hypotheses.get(hypothesis_id)

    def list_all(self) -> List[Hypothesis]:
        """Returns all hypotheses in registration order."""
        return list(self._hypotheses.values())

    def list_confirmed(self) -> List[Hypothesis]:
        """Returns confirmed hypotheses."""
        return [h for h in self._hypotheses.values() if h.status == "confirmed"]

    def list_rejected(self) -> List[Hypothesis]:
        """Returns rejected hypotheses."""
        return [h for h in self._hypotheses.values() if h.status == "rejected"]

    def apply_evaluation(
        self,
        hypothesis_id: str,
        evaluation: ExperimentEvaluation,
    ) -> Hypothesis:
        """
        Transitions hypothesis state based on deterministic experiment evaluation.

        Transitions:
          - confirmed / flag_found: status -> 'confirmed', failure_count = 0
          - rejected: status -> 'rejected', failure_count += 1
          - inconclusive: status -> 'inconclusive' (or remains active if failures within budget), failure_count += 1
        """
        target = self._hypotheses.get(hypothesis_id)
        if not target:
            raise UnknownHypothesisError(
                f"Hypothesis '{hypothesis_id}' is not registered. Refusing to apply evaluation."
            )

        target.attempts += 1

        if evaluation.outcome in ["confirmed", "flag_found"]:
            target.status = "confirmed"
            target.failure_count = 0
            for ev in evaluation.supporting_evidence:
                if ev and ev not in target.supporting_evidence:
                    target.supporting_evidence.append(ev)
        elif evaluation.outcome == "rejected":
            target.status = "rejected"
            target.failure_count += 1
            for ev in evaluation.contradicting_evidence:
                if ev and ev not in target.contradicting_evidence:
                    target.contradicting_evidence.append(ev)
        elif evaluation.outcome == "inconclusive":
            target.status = "inconclusive"
            target.failure_count += 1

        return target

    def recommend_pivot(self) -> bool:
        """
        Recommends whether a hypothesis pivot is required based on failure budget
        or terminal hypothesis status.
        """
        active = self.get_active()
        if not active:
            return True

        # If active hypothesis has been rejected, pivot is required
        if active.status == "rejected":
            return True

        # If consecutive failures exceed the budget, pivot is required
        if active.failure_count >= self.max_consecutive_failures:
            return True

        # Confirmed hypothesis does NOT force a pivot (subsequent experiments can build on it)
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "max_consecutive_failures": self.max_consecutive_failures,
            "active_id": self._active_id,
            "hypotheses": [h.model_dump() for h in self._hypotheses.values()],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HypothesisManager":
        manager = cls(max_consecutive_failures=data.get("max_consecutive_failures", 2))
        for h_data in data.get("hypotheses", []):
            h = Hypothesis.model_validate(h_data)
            manager._hypotheses[h.id] = h
        manager._active_id = data.get("active_id")
        return manager

    def save(self, filepath: Path) -> None:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")

    @classmethod
    def load(cls, filepath: Path) -> "HypothesisManager":
        if not filepath.is_file():
            return cls()
        try:
            data = json.loads(filepath.read_text(encoding="utf-8"))
            return cls.from_dict(data)
        except Exception:
            return cls()
