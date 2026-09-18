import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional
from rich.console import Console

from ..models import AdvisorGuidance, ExecutionAction, ExecutionResult

console = Console()

SAFE_ENV_KEYS = ["PATH", "HOME", "LANG", "LC_ALL", "PYTHONPATH"]

class RestrictedLocalExecutor:
    """
    Hardened local script executor.
    Guarantees:
    1. NEVER runs free-form model text via shell=True.
    2. Strict environment isolation (strips platform tokens, sessions, cookies, GitHub keys).
    3. Evidence-based result verification (exit code 0 alone is INCONCLUSIVE without evidence).
    """

    def __init__(
        self,
        flag_format_regex: str = r"FLAG\{[^\n\r\}]+\}",
        timeout: int = 60,
        flag_format: Optional[str] = None,
    ):
        self.flag_format_regex = flag_format or flag_format_regex
        self.timeout = timeout

    def _build_safe_env(self, extra_vars: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        env = {k: os.environ[k] for k in SAFE_ENV_KEYS if k in os.environ}
        if "PATH" not in env:
            env["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        if extra_vars:
            # Block forbidden keys
            for k, v in extra_vars.items():
                if not any(bad in k.upper() for bad in ["TOKEN", "COOKIE", "SECRET", "AUTH", "PASS"]):
                    env[k] = str(v)
        return env

    def execute(self, challenge_context: Dict[str, Any], guidance: AdvisorGuidance) -> ExecutionResult:
        if "work_dir" in challenge_context:
            work_dir = Path(challenge_context["work_dir"]).resolve()
        elif "challenge_dir" in challenge_context:
            cd = Path(challenge_context["challenge_dir"]).resolve()
            work_dir = (cd / "work") if (cd / "work").is_dir() else cd
        else:
            work_dir = Path.cwd().resolve()

        iteration = challenge_context.get("iteration", 1)
        experiment_id = f"EXP-{iteration:03d}"

        if not work_dir.is_dir():
            return ExecutionResult(
                experiment_id=experiment_id,
                status="ERROR",
                return_code=-1,
                actions=["check_work_dir"],
                observed=f"Work directory does not exist: {work_dir}",
                evidence=[],
                flag_candidates=[],
            )

        actions_performed: List[str] = []
        observed_logs: List[str] = []
        evidence_found: List[str] = []
        flag_candidates: List[str] = []
        final_return_code: Optional[int] = None
        stdout_tail: str = ""
        stderr_tail: str = ""

        # Default task: execute solve.py in work_dir if no guidance actions
        solve_script = work_dir / "solve.py"
        actions_to_run: List[ExecutionAction] = []

        if guidance.next_actions:
            for act in guidance.next_actions:
                cmd = act.command_or_task.strip()
                if cmd.startswith("python3 ") or cmd == "python3":
                    parts = cmd.split()
                    actions_to_run.append(ExecutionAction(kind="run_python", argv=parts, timeout=self.timeout))
                elif cmd.startswith("./"):
                    actions_to_run.append(ExecutionAction(kind="run_binary", argv=[cmd], timeout=self.timeout))
                else:
                    parts = cmd.split()
                    if parts:
                        actions_to_run.append(ExecutionAction(kind="tool", argv=parts, timeout=self.timeout))
        elif solve_script.is_file():
            actions_to_run.append(ExecutionAction(
                kind="run_python",
                argv=["python3", "solve.py"],
                path="solve.py",
                timeout=self.timeout
            ))
        else:
            actions_to_run.append(ExecutionAction(
                kind="list_files",
                argv=["ls", "-la"],
                timeout=10
            ))

        safe_env = self._build_safe_env(challenge_context.get("env_vars"))

        for action in actions_to_run:
            argv = action.argv
            actions_performed.append(" ".join(argv))
            console.print(f"[dim]⚡ [RestrictedExecutor] Executing (shell=False): {' '.join(argv)}[/dim]")

            try:
                proc = subprocess.run(
                    argv,
                    shell=False,  # P0 HARDENED: NEVER shell=True
                    cwd=str(work_dir),
                    env=safe_env,
                    capture_output=True,
                    text=True,
                    timeout=action.timeout
                )
                final_return_code = proc.returncode
                stdout_tail = proc.stdout[-1500:] if proc.stdout else ""
                stderr_tail = proc.stderr[-1500:] if proc.stderr else ""

                combined_out = (proc.stdout or "") + "\n" + (proc.stderr or "")

                # 1. Flag Candidate extraction
                search_pattern = self.flag_format_regex.strip("^$")
                matches = re.findall(search_pattern, combined_out)
                for m in matches:
                    if m not in flag_candidates:
                        flag_candidates.append(m)

                # Check work/flag.txt
                flag_file = work_dir / "flag.txt"
                if flag_file.is_file():
                    content = flag_file.read_text(encoding="utf-8").strip()
                    if content and content not in flag_candidates:
                        flag_candidates.append(content)

                # 2. Evidence extraction
                for req_ev in guidance.requested_evidence:
                    if req_ev and req_ev.lower() in combined_out.lower():
                        evidence_found.append(f"Matched requested evidence: '{req_ev}'")

                for act_def in guidance.next_actions:
                    if act_def.expected_evidence and act_def.expected_evidence.lower() in combined_out.lower():
                        evidence_found.append(f"Observed expected evidence: '{act_def.expected_evidence}'")

                observed_logs.append(f"Return code {proc.returncode}. Output length: {len(combined_out)}")

            except subprocess.TimeoutExpired:
                final_return_code = -9
                stderr_tail = f"Command timed out after {action.timeout}s"
                observed_logs.append(f"Command timed out ({action.timeout}s)")
            except Exception as e:
                final_return_code = -1
                stderr_tail = str(e)
                observed_logs.append(f"Execution failed: {e}")

        # Determine evidence-based status
        if flag_candidates:
            status = "FLAG_FOUND"
        elif final_return_code == -9 or "timed out" in " ".join(observed_logs).lower():
            status = "ERROR"
        elif final_return_code == 0 and evidence_found:
            status = "CONFIRMED"
        elif final_return_code == 0:
            # P0: Exit code 0 alone without evidence is INCONCLUSIVE
            status = "INCONCLUSIVE"
        else:
            status = "REJECTED"

        obs_text = " | ".join(observed_logs)
        if stdout_tail:
            obs_text += f"\nStdout: {stdout_tail}"
        if stderr_tail:
            obs_text += f"\nStderr: {stderr_tail}"

        return ExecutionResult(
            experiment_id=experiment_id,
            status=status,
            return_code=final_return_code,
            actions=actions_performed,
            observed=obs_text,
            evidence=evidence_found,
            flag_candidates=flag_candidates,
            stdout_tail=stdout_tail,
            stderr_tail=stderr_tail,
        )
