import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ..models import ExecutionAction, Experiment, ExperimentCandidate


def normalize_action(action: ExecutionAction) -> Dict[str, Any]:
    norm_path = str(action.path or "").strip()
    if norm_path.startswith("./"):
        norm_path = norm_path[2:]
    return {
        "kind": str(action.kind).strip().lower(),
        "tool": str(action.tool or "").strip().lower(),
        "path": norm_path,
        "argv": [str(arg).strip() for arg in (action.argv or [])],
    }


def compute_material_signature(exp: Union[Experiment, ExperimentCandidate, Dict[str, Any]]) -> str:
    """
    Computes a canonical deterministic material signature for an experiment candidate or experiment.
    Two experiments are materially equivalent if they test the same hypothesis with identical
    actions, operands, and expected/contradicting evidence.
    NATURAL-LANGUAGE INTENT AND RATIONALE ARE EXCLUDED so phrasing changes cannot bypass retry suppression.
    """
    if isinstance(exp, dict):
        hypo_id = str(exp.get("hypothesis_id", "")).strip().upper()
        actions_raw = exp.get("execution_plan") or []
        expected = sorted([str(e).strip().lower() for e in (exp.get("expected_evidence") or []) if str(e).strip()])
        contra = sorted([str(e).strip().lower() for e in (exp.get("contradicting_evidence") or []) if str(e).strip()])
    else:
        hypo_id = str(getattr(exp, "hypothesis_id", "")).strip().upper()
        actions_raw = getattr(exp, "actions_to_run", None) or getattr(exp, "execution_plan", None) or []
        expected = sorted([str(e).strip().lower() for e in getattr(exp, "expected_evidence", []) if str(e).strip()])
        contra = sorted([str(e).strip().lower() for e in getattr(exp, "contradicting_evidence", []) if str(e).strip()])

    norm_actions = []
    for a in actions_raw:
        if isinstance(a, ExecutionAction):
            norm_actions.append(normalize_action(a))
        elif isinstance(a, dict):
            norm_path = str(a.get("path", "")).strip()
            if norm_path.startswith("./"):
                norm_path = norm_path[2:]
            norm_actions.append({
                "kind": str(a.get("kind", "")).strip().lower(),
                "tool": str(a.get("tool", "")).strip().lower(),
                "path": norm_path,
                "argv": [str(arg).strip() for arg in (a.get("argv") or [])],
            })

    payload = {
        "hypothesis_id": hypo_id,
        "actions": norm_actions,
        "expected_evidence": expected,
        "contradicting_evidence": contra,
    }
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


# Canonical alias for backward compatibility
compute_experiment_signature = compute_material_signature


def compute_context_fingerprint(
    work_dir: Optional[Path] = None,
    input_dir: Optional[Path] = None,
    connection_info: Optional[str] = None,
    capabilities_hash: Optional[str] = None,
    knowledge_revision: Optional[str] = None,
) -> str:
    """
    Computes a deterministic fingerprint of the execution environment and challenge artifacts.
    A rejected experiment may become eligible again if any of these material factors change
    (e.g., solve.py was modified, new attachment was unpacked, target IP changed).
    """
    h = hashlib.sha256()

    if connection_info:
        h.update(f"conn:{connection_info.strip()}".encode("utf-8"))

    if capabilities_hash:
        h.update(f"caps:{capabilities_hash.strip()}".encode("utf-8"))

    if knowledge_revision:
        h.update(f"krev:{knowledge_revision.strip()}".encode("utf-8"))

    for d in [input_dir, work_dir]:
        if d and Path(d).is_dir():
            for root, _, files in os.walk(str(d)):
                for f in sorted(files):
                    fpath = Path(root) / f
                    if fpath.is_file() and not f.endswith(".lock") and not f.endswith(".tmp"):
                        try:
                            st = fpath.stat()
                            h.update(f"{f}:{st.st_size}:{int(st.st_mtime)}".encode("utf-8"))
                        except Exception:
                            pass

    return h.hexdigest()


def are_experiments_equivalent(
    exp_a: Union[Experiment, ExperimentCandidate, Dict[str, Any]],
    exp_b: Union[Experiment, ExperimentCandidate, Dict[str, Any]],
) -> bool:
    """Check if two experiment proposals or executions are functionally equivalent."""
    return compute_material_signature(exp_a) == compute_material_signature(exp_b)

