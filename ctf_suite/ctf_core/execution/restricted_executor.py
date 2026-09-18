import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional
from rich.console import Console

from ..models import AdvisorGuidance, ExecutionAction, ExecutionResult
from .evaluator import ExecutionResultEvaluator

console = Console()

SAFE_ENV_KEYS = ["PATH", "HOME", "LANG", "LC_ALL", "PYTHONPATH"]

# Explicit allowlist of permissible local analysis tools.
# Arbitrary model-supplied binaries or shell commands outside this set are strictly rejected.
ALLOWED_ANALYSIS_TOOLS = {
    "file",
    "strings",
    "readelf",
    "objdump",
    "checksec",
    "nm",
    "ltrace",
    "strace",
    "ropper",
    "seccomp-tools",
}

class RestrictedLocalExecutor:
    """
    Hardened local script executor.
    Guarantees:
    1. NEVER runs free-form model text via shell=True.
    2. Model-generated next_actions prose is NEVER executed. Only structured execution_plan is executable.
    3. Target paths (run_python_file, run_binary, read_file) must resolve strictly inside work_dir.
    4. Tools must be explicitly registered in ALLOWED_ANALYSIS_TOOLS; arbitrary executables are rejected.
    5. Strict environment isolation (strips platform tokens, sessions, cookies, GitHub keys).
    6. Evidence-based result verification (exit code 0 alone is INCONCLUSIVE without evidence).
    NOTE: restricted-local is NOT a full sandbox (a local Python script can still access files/network).
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
            for k, v in extra_vars.items():
                if not any(bad in k.upper() for bad in ["TOKEN", "COOKIE", "SECRET", "AUTH", "PASS", "KEY"]):
                    env[k] = str(v)
        return env

    def _resolve_and_validate_path(self, target: Optional[str], work_dir: Path) -> Path:
        """
        Validates that a path is strictly contained within work_dir.
        Rejects traversal (../../), home directory paths (~), and absolute host paths.
        """
        if not target:
            raise ValueError("Target path must not be empty")

        p = Path(target)
        if p.is_absolute():
            resolved = p.resolve()
        else:
            resolved = (work_dir / p).resolve()

        resolved_work = work_dir.resolve()
        if not resolved.is_relative_to(resolved_work):
            raise PermissionError(f"Path traversal blocked: target '{target}' resolves to '{resolved}', outside '{resolved_work}'")

        return resolved

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
        stdout_acc: List[str] = []
        stderr_acc: List[str] = []
        final_return_code: Optional[int] = None
        timed_out = False
        error_msg: Optional[str] = None

        # Build execution list strictly from guidance.execution_plan
        # Notice: guidance.next_actions is human-readable and MUST NOT be executed.
        actions_to_run: List[ExecutionAction] = []

        if getattr(guidance, "execution_plan", None):
            actions_to_run.extend(guidance.execution_plan)
        else:
            # Safe default when execution_plan is absent: run existing work/solve.py if present
            solve_script = work_dir / "solve.py"
            if solve_script.is_file():
                actions_to_run.append(ExecutionAction(
                    kind="run_solver",
                    argv=["python3", "solve.py"],
                    path="solve.py",
                    timeout=self.timeout,
                ))
            else:
                actions_to_run.append(ExecutionAction(
                    kind="list_files",
                    argv=["ls", "-la"],
                    timeout=10,
                ))

        safe_env = self._build_safe_env(challenge_context.get("env_vars"))

        for action in actions_to_run:
            kind = action.kind
            argv: List[str] = []

            try:
                if kind in ["run_solver", "run_python_file"]:
                    target_script = self._resolve_and_validate_path(action.path or "solve.py", work_dir)
                    if not target_script.is_file():
                        raise FileNotFoundError(f"Python target file not found: {target_script}")
                    rel_target = str(target_script.relative_to(work_dir))
                    argv = ["python3", rel_target]
                    if action.argv and len(action.argv) > 1:
                        # Allow extra arguments after script name if clean
                        argv.extend([arg for arg in action.argv[1:] if not any(c in arg for c in [";", "&", "|", "`", "$"])])

                elif kind == "run_binary":
                    target_bin = self._resolve_and_validate_path(action.path or (action.argv[0] if action.argv else None), work_dir)
                    if not target_bin.is_file():
                        raise FileNotFoundError(f"Binary target file not found: {target_bin}")
                    rel_target = f"./{target_bin.relative_to(work_dir)}"
                    argv = [rel_target]
                    if action.argv and len(action.argv) > 1:
                        argv.extend(action.argv[1:])

                elif kind == "read_file":
                    target_file = self._resolve_and_validate_path(action.path or (action.argv[0] if action.argv else None), work_dir)
                    if not target_file.is_file():
                        raise FileNotFoundError(f"Read target file not found: {target_file}")
                    rel_target = str(target_file.relative_to(work_dir))
                    argv = ["cat", rel_target]

                elif kind == "list_files":
                    argv = ["ls", "-la"]

                elif kind == "analysis_tool":
                    tool_name = action.tool or (action.argv[0] if action.argv else None)
                    if not tool_name or tool_name not in ALLOWED_ANALYSIS_TOOLS:
                        raise PermissionError(f"Analysis tool '{tool_name}' is not in allowed registry: {sorted(ALLOWED_ANALYSIS_TOOLS)}")
                    if not shutil.which(tool_name):
                        raise FileNotFoundError(f"Analysis tool '{tool_name}' not installed on host PATH")

                    # Sanitize tool arguments
                    clean_argv = [tool_name]
                    for arg in action.argv[1:]:
                        # If an argument is a path, validate it doesn't escape work_dir
                        if "/" in arg or ".." in arg:
                            resolved_arg = self._resolve_and_validate_path(arg, work_dir)
                            clean_argv.append(str(resolved_arg.relative_to(work_dir)))
                        else:
                            clean_argv.append(arg)
                    argv = clean_argv

                else:
                    raise ValueError(f"Unsupported execution action kind: '{kind}'")

            except Exception as e:
                console.print(f"[bold red]❌ Rejected execution action ({kind}): {e}[/bold red]")
                error_msg = str(e)
                final_return_code = -1
                actions_performed.append(f"rejected:{kind}:{e}")
                break

            actions_performed.append(" ".join(argv))
            console.print(f"[dim]⚡ [RestrictedExecutor] Executing (shell=False): {' '.join(argv)}[/dim]")

            try:
                proc = subprocess.run(
                    argv,
                    shell=False,
                    cwd=str(work_dir),
                    env=safe_env,
                    capture_output=True,
                    text=True,
                    timeout=action.timeout or self.timeout,
                )
                final_return_code = proc.returncode
                if proc.stdout:
                    stdout_acc.append(proc.stdout)
                if proc.stderr:
                    stderr_acc.append(proc.stderr)

            except subprocess.TimeoutExpired:
                final_return_code = -9
                timed_out = True
                stderr_acc.append(f"Command timed out after {action.timeout}s")
                break
            except Exception as e:
                final_return_code = -1
                error_msg = str(e)
                stderr_acc.append(str(e))
                break

        full_stdout = "\n".join(stdout_acc)
        full_stderr = "\n".join(stderr_acc)

        return ExecutionResultEvaluator.build_result(
            experiment_id=experiment_id,
            return_code=final_return_code,
            stdout=full_stdout,
            stderr=full_stderr,
            actions_performed=actions_performed,
            work_dir=work_dir,
            guidance=guidance,
            flag_format_regex=self.flag_format_regex,
            timed_out=timed_out,
            error_message=error_msg,
        )
