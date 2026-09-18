import os
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional
from ..models import AdvisorGuidance, ExecutionResult

DEFAULT_FLAG_REGEX = re.compile(
    r'(?i)(?:[a-z0-9_\-]*?(?:flag|ctf|sec|pwnbox|svattt|hcmus|kcsc|htb|dice|defcon|cyber|null0rigin))\{[^\r\n\}]{4,120}\}'
)


class LocalScriptExecutor:
    """
    Default Local Closed-Loop Executor.
    Executes solver scripts or suggested commands in the challenge's work/ directory,
    collects stdout/stderr, extracts evidence and candidate flags.
    """

    def __init__(self, timeout: int = 60, flag_format_regex: Optional[str] = None):
        self.timeout = timeout
        self.flag_regex = re.compile(flag_format_regex) if flag_format_regex else DEFAULT_FLAG_REGEX

    def extract_flags(self, text: str) -> List[str]:
        if not text:
            return []
        matches = self.flag_regex.findall(text)
        return list(dict.fromkeys(matches))

    def execute(
        self,
        challenge_context: Dict[str, Any],
        guidance: AdvisorGuidance,
    ) -> ExecutionResult:
        work_dir = Path(challenge_context.get("work_dir", ".")).resolve()
        work_dir.mkdir(parents=True, exist_ok=True)
        
        iteration = challenge_context.get("iteration", 1)
        experiment_id = f"EXP-{iteration:03d}"

        actions_taken = []
        stdout_combined = []
        stderr_combined = []
        flag_candidates = []

        # 1. Check if flag.txt already exists
        flag_file = work_dir / "flag.txt"
        if flag_file.is_file():
            content = flag_file.read_text(encoding="utf-8").strip()
            flags = self.extract_flags(content)
            if flags:
                flag_candidates.extend(flags)

        # 2. Run solve.py in work_dir if exists
        solve_file = work_dir / "solve.py"
        if solve_file.is_file() and not flag_candidates:
            actions_taken.append(f"python3 {solve_file.name}")
            try:
                env = dict(os.environ)
                proc = subprocess.run(
                    ["python3", str(solve_file)],
                    cwd=str(work_dir),
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    env=env,
                )
                stdout_combined.append(proc.stdout)
                stderr_combined.append(proc.stderr)
                
                flags = self.extract_flags(proc.stdout + "\n" + proc.stderr)
                if flags:
                    flag_candidates.extend(flags)
                
                # Check flag.txt again after run
                if flag_file.is_file():
                    content = flag_file.read_text(encoding="utf-8").strip()
                    file_flags = self.extract_flags(content)
                    for ff in file_flags:
                        if ff not in flag_candidates:
                            flag_candidates.append(ff)
                            
            except subprocess.TimeoutExpired:
                stderr_combined.append(f"Execution timed out after {self.timeout}s")
            except Exception as e:
                stderr_combined.append(f"Execution error: {e}")

        # 3. If guidance provided specific shell actions and still no flag, run them
        for act in guidance.next_actions:
            if flag_candidates:
                break
            if act.type in ["command", "bash", "shell"] and act.command_or_task:
                cmd = act.command_or_task.strip()
                # Run command safely in work_dir
                actions_taken.append(cmd)
                try:
                    proc = subprocess.run(
                        cmd,
                        shell=True,
                        cwd=str(work_dir),
                        capture_output=True,
                        text=True,
                        timeout=self.timeout,
                    )
                    stdout_combined.append(proc.stdout)
                    stderr_combined.append(proc.stderr)
                    flags = self.extract_flags(proc.stdout + "\n" + proc.stderr)
                    if flags:
                        flag_candidates.extend(flags)
                except Exception as e:
                    stderr_combined.append(str(e))

        all_stdout = "\n".join(stdout_combined)
        all_stderr = "\n".join(stderr_combined)

        # Determine status
        if flag_candidates:
            status = "FLAG_FOUND"
            observed = f"Discovered {len(flag_candidates)} flag candidate(s): {flag_candidates[0]}"
        elif all_stderr and not all_stdout:
            status = "ERROR"
            observed = f"Command exited with errors: {all_stderr[:200]}"
        elif all_stdout:
            status = "CONFIRMED"
            observed = f"Executed successfully, output tail: {all_stdout[-300:]}"
        else:
            status = "INCONCLUSIVE"
            observed = "No output produced by solver or actions."

        return ExecutionResult(
            experiment_id=experiment_id,
            status=status,
            actions=actions_taken,
            observed=observed,
            evidence=[observed] if observed else [],
            flag_candidates=flag_candidates,
            stdout_tail=all_stdout[-500:] if all_stdout else None,
            stderr_tail=all_stderr[-500:] if all_stderr else None,
        )
