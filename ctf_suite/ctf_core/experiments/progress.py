from datetime import datetime
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field


def normalize_evidence_key(raw_evidence: str) -> str:
    """
    Normalizes an evidence string into a canonical fingerprint for duplicate detection.
    Example:
      "Observed expected evidence: 'SECRET42'" -> "secret42"
      "Matched requested evidence: 'flag{'" -> "flag{"
      "CANARY: Disabled" -> "canary:disabled"
    """
    if not raw_evidence:
        return ""
    text = str(raw_evidence).strip().lower()
    # Strip common prefixes
    for prefix in [
        "matched requested evidence:",
        "observed expected evidence:",
        "observed contradicting evidence:",
        "evidence found:",
        "evidence:",
    ]:
        if text.startswith(prefix):
            text = text[len(prefix):].strip()
    # Strip enclosing quotes
    text = text.strip("\"'").strip()
    # Collapse multiple whitespace
    text = re.sub(r"\s+", " ", text)
    return text


class SolverProgress(BaseModel):
    total_experiments: int = 0
    new_evidence_count: int = 0
    hypothesis_transitions: int = 0
    suppressed_experiments: int = 0
    rounds_with_zero_new_evidence: int = 0
    pivot_count: int = 0
    known_evidence: List[str] = Field(default_factory=list)
    recent_signatures: List[str] = Field(default_factory=list)
    last_updated: str = Field(default_factory=lambda: datetime.now().isoformat())


class SolverProgressTracker:
    """
    Deterministic solver progress and stagnation tracker.
    Avoids subjective progress scores; tracks factual state changes.
    """

    def __init__(self, advisor_dir_or_file: Path):
        p = Path(advisor_dir_or_file)
        if p.is_dir() or p.name != "progress.json":
            self.file_path = p / "progress.json"
        else:
            self.file_path = p
        self.progress = self._load()

    def _load(self) -> SolverProgress:
        if self.file_path.is_file():
            try:
                data = json.loads(self.file_path.read_text(encoding="utf-8"))
                return SolverProgress.model_validate(data)
            except Exception:
                pass
        return SolverProgress()

    def save(self) -> None:
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        self.progress.last_updated = datetime.now().isoformat()
        self.file_path.write_text(
            self.progress.model_dump_json(indent=2),
            encoding="utf-8"
        )

    def is_known_evidence(self, evidence: str) -> bool:
        norm = normalize_evidence_key(evidence)
        if not norm:
            return True  # Empty/whitespace is not new evidence
        return norm in [normalize_evidence_key(k) for k in self.progress.known_evidence]

    def record_evidence(self, evidence_items: List[str]) -> List[str]:
        """
        Filters and records evidence items, returning only genuinely new evidence items.
        Updates zero-new-evidence counter accordingly.
        """
        new_items: List[str] = []
        for ev in evidence_items:
            norm = normalize_evidence_key(ev)
            if norm and not self.is_known_evidence(norm):
                self.progress.known_evidence.append(norm)
                new_items.append(norm)

        if new_items:
            self.progress.new_evidence_count += len(new_items)
            self.progress.rounds_with_zero_new_evidence = 0
        else:
            self.progress.rounds_with_zero_new_evidence += 1

        self.save()
        return new_items

    def record_experiment_attempt(self, signature: str) -> None:
        self.progress.total_experiments += 1
        self.progress.recent_signatures.append(signature)
        if len(self.progress.recent_signatures) > 50:
            self.progress.recent_signatures = self.progress.recent_signatures[-50:]
        self.save()

    def record_suppression(self) -> None:
        self.progress.suppressed_experiments += 1
        self.save()

    def record_hypothesis_transition(self) -> None:
        self.progress.hypothesis_transitions += 1
        self.save()

    def record_pivot(self) -> None:
        self.progress.pivot_count += 1
        self.progress.rounds_with_zero_new_evidence = 0
        self.save()

    def is_stagnated(self, threshold: int = 3) -> bool:
        """
        Scientific stagnation occurs when multiple consecutive completed experiments
        yield zero new evidence and no hypothesis transitions.
        """
        return (
            self.progress.rounds_with_zero_new_evidence >= threshold
            and self.progress.total_experiments >= threshold
        )
