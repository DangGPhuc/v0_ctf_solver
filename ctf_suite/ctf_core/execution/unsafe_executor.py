import os
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional
from rich.console import Console

from ..models import AdvisorGuidance, ExecutionResult

console = Console()

class UnsafeLocalExecutor:
    """
    OPT-IN ONLY: Raw shell executor with shell=True.
    DANGEROUS: Should only be used when explicitly requested via --executor unsafe-local.
    """

    def __init__(self, flag_format_regex: str = r"FLAG\{[^\n\r\}]+\}"):
        self.flag_format_regex = flag_format_regex
        console.print("[bold red]🚨 WARNING: UnsafeLocalExecutor is enabled! Raw shell commands will execute without sandboxing![/bold red]")

    def execute(self, challenge_context: Dict[str, Any], guidance: AdvisorGuidance) -> ExecutionResult:
        work_dir = Path(challenge_context.get("work_dir", ".")).resolve()
        iteration = challenge_context.get("iteration", 1)
        experiment_id = (
            challenge_context.get("experiment_id")
            or f"EXP-{iteration:03d}"
        )

        actions_performed: List[str] = []
        observed_logs: List[str] = []
        evidence_found: List[str] = []
        flag_candidates: List[str] = []
        final_return_code: Optional[int] = None
        stdout_tail: str = ""
        stderr_tail: str = ""

        # Run solve.py or actions
        commands = ["python3 solve.py"]
        for act in guidance.next_actions:
            if act.command_or_task and act.command_or_task not in commands:
                commands.append(act.command_or_task)

        for cmd in commands:
            actions_performed.append(cmd)
            console.print(f"[bold yellow]⚠️ [UnsafeExecutor] Executing (shell=True): {cmd}[/bold yellow]")
            try:
                proc = subprocess.run(
                    cmd,
                    shell=True,
                    cwd=str(work_dir),
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                final_return_code = proc.returncode
                stdout_tail = proc.stdout[-1500:] if proc.stdout else ""
                stderr_tail = proc.stderr[-1500:] if proc.stderr else ""
                combined_out = (proc.stdout or "") + "\n" + (proc.stderr or "")

                matches = re.findall(self.flag_format_regex, combined_out)
                for m in matches:
                    if m not in flag_candidates:
                        flag_candidates.append(m)

                flag_file = work_dir / "flag.txt"
                if flag_file.is_file():
                    content = flag_file.read_text(encoding="utf-8").strip()
                    if content and content not in flag_candidates:
                        flag_candidates.append(content)

                for req_ev in guidance.requested_evidence:
                    if req_ev and req_ev.lower() in combined_out.lower():
                        evidence_found.append(f"Matched requested evidence: '{req_ev}'")

            except Exception as e:
                final_return_code = -1
                stderr_tail = str(e)

        status = "FLAG_FOUND" if flag_candidates else ("CONFIRMED" if final_return_code == 0 and evidence_found else ("INCONCLUSIVE" if final_return_code == 0 else "REJECTED"))

        return ExecutionResult(
            experiment_id=experiment_id,
            status=status,
            return_code=final_return_code,
            actions=actions_performed,
            observed=" | ".join(observed_logs),
            evidence=evidence_found,
            flag_candidates=flag_candidates,
            stdout_tail=stdout_tail,
            stderr_tail=stderr_tail,
        )
