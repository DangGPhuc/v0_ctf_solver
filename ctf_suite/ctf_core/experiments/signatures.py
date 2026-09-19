import hashlib
import json
from typing import Any, Dict, List, Union

from ..models import ExecutionAction, Experiment, ExperimentCandidate


def normalize_action(action: ExecutionAction) -> Dict[str, Any]:
    return {
        "kind": str(action.kind).strip().lower(),
        "tool": str(action.tool or "").strip().lower(),
        "path": str(action.path or "").strip(),
        "argv": [str(arg).strip() for arg in (action.argv or [])],
    }


def compute_experiment_signature(exp: Union[Experiment, ExperimentCandidate, Dict[str, Any]]) -> str:
    """
    Computes a canonical deterministic signature for an experiment candidate or experiment.
    Two experiments are materially equivalent if they test the same hypothesis with identical
    actions, intent, and expected/contradicting evidence.
    """
    if isinstance(exp, dict):
        hypo_id = str(exp.get("hypothesis_id", "")).strip().upper()
        intent = str(exp.get("intent", "")).strip().lower()
        actions_raw = exp.get("execution_plan") or []
        expected = sorted([str(e).strip().lower() for e in (exp.get("expected_evidence") or []) if str(e).strip()])
        contra = sorted([str(e).strip().lower() for e in (exp.get("contradicting_evidence") or []) if str(e).strip()])
    else:
        hypo_id = str(getattr(exp, "hypothesis_id", "")).strip().upper()
        intent = str(getattr(exp, "intent", "")).strip().lower()
        actions_raw = getattr(exp, "actions_to_run", None) or getattr(exp, "execution_plan", None) or []
        expected = sorted([str(e).strip().lower() for e in getattr(exp, "expected_evidence", []) if str(e).strip()])
        contra = sorted([str(e).strip().lower() for e in getattr(exp, "contradicting_evidence", []) if str(e).strip()])

    norm_actions = []
    for a in actions_raw:
        if isinstance(a, ExecutionAction):
            norm_actions.append(normalize_action(a))
        elif isinstance(a, dict):
            norm_actions.append({
                "kind": str(a.get("kind", "")).strip().lower(),
                "tool": str(a.get("tool", "")).strip().lower(),
                "path": str(a.get("path", "")).strip(),
                "argv": [str(arg).strip() for arg in (a.get("argv") or [])],
            })

    payload = {
        "hypothesis_id": hypo_id,
        "intent": intent,
        "actions": norm_actions,
        "expected_evidence": expected,
        "contradicting_evidence": contra,
    }
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def are_experiments_equivalent(
    exp_a: Union[Experiment, ExperimentCandidate, Dict[str, Any]],
    exp_b: Union[Experiment, ExperimentCandidate, Dict[str, Any]],
) -> bool:
    """Check if two experiment proposals or executions are functionally equivalent."""
    return compute_experiment_signature(exp_a) == compute_experiment_signature(exp_b)
