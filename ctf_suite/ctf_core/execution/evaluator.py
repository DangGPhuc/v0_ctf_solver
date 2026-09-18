import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models import AdvisorGuidance, ExecutionResult

class ExecutionResultEvaluator:
    """
    Reusable evaluator for execution outputs (both container and local).
    Extracts flags, checks requested evidence, and determines execution status
    without rerunning any commands.
    """

    @staticmethod
    def build_result(
        experiment_id: str,
        return_code: Optional[int],
        stdout: str,
        stderr: str,
        actions_performed: List[str],
        work_dir: Optional[Path] = None,
        guidance: Optional[AdvisorGuidance] = None,
        flag_format_regex: str = r"FLAG\{[^\n\r\}]+\}",
        timed_out: bool = False,
        error_message: Optional[str] = None,
    ) -> ExecutionResult:
        combined_out = (stdout or "") + "\n" + (stderr or "")
        flag_candidates: List[str] = []
        evidence_found: List[str] = []

        # 1. Flag Candidate extraction from stdout/stderr
        search_pattern = flag_format_regex.strip("^$")
        try:
            matches = re.findall(search_pattern, combined_out)
            for m in matches:
                if m not in flag_candidates:
                    flag_candidates.append(m)
        except Exception:
            pass

        # Check work_dir/flag.txt if work_dir provided
        if work_dir and Path(work_dir).is_dir():
            flag_file = Path(work_dir) / "flag.txt"
            if flag_file.is_file():
                try:
                    content = flag_file.read_text(encoding="utf-8").strip()
                    if content and content not in flag_candidates:
                        flag_candidates.append(content)
                except Exception:
                    pass

        # 2. Evidence extraction
        if guidance:
            for req_ev in guidance.requested_evidence:
                if req_ev and req_ev.lower() in combined_out.lower():
                    evidence_found.append(f"Matched requested evidence: '{req_ev}'")

            for act_def in getattr(guidance, "next_actions", []):
                if getattr(act_def, "expected_evidence", None):
                    if act_def.expected_evidence.lower() in combined_out.lower():
                        evidence_found.append(f"Observed expected evidence: '{act_def.expected_evidence}'")

        # 3. Status determination
        if flag_candidates:
            status = "FLAG_FOUND"
        elif timed_out or return_code == -9:
            status = "ERROR"
        elif error_message:
            status = "ERROR"
        elif return_code == 0 and evidence_found:
            status = "CONFIRMED"
        elif return_code == 0:
            status = "INCONCLUSIVE"
        elif return_code is None:
            status = "ERROR"
        else:
            status = "REJECTED"

        stdout_tail = stdout[-1500:] if stdout else ""
        stderr_tail = stderr[-1500:] if stderr else ""
        if error_message:
            stderr_tail = (stderr_tail + "\n" + error_message).strip()

        obs_lines = []
        if return_code is not None:
            obs_lines.append(f"Return code {return_code}. Output length: {len(combined_out)}")
        if timed_out:
            obs_lines.append("Execution timed out")
        if error_message:
            obs_lines.append(f"Execution error: {error_message}")
        if stdout_tail:
            obs_lines.append(f"Stdout: {stdout_tail}")
        if stderr_tail:
            obs_lines.append(f"Stderr: {stderr_tail}")

        return ExecutionResult(
            experiment_id=experiment_id,
            status=status,
            return_code=return_code,
            actions=actions_performed,
            observed=" | ".join(obs_lines[:2]) + ("\n" + "\n".join(obs_lines[2:]) if len(obs_lines) > 2 else ""),
            evidence=evidence_found,
            flag_candidates=flag_candidates,
            stdout_tail=stdout_tail,
            stderr_tail=stderr_tail,
        )
