import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional
from rich.console import Console

from ..models import AdvisorGuidance, ExecutionAction, ExecutionResult
from .artifacts import ArtifactResolver, ArtifactResolutionError
from .evaluator import ExecutionResultEvaluator
from .policy import (
    ActionPolicy,
    ExecutionPolicyError,
    ALLOWED_ANALYSIS_TOOLS,
    SAFE_ENV_KEYS,
)
from .runner import ExecutionRunner

console = Console()


class RestrictedLocalExecutor:
    """
    Hardened local script executor.
    Guarantees:
    1. NEVER runs free-form model text via shell=True.
    2. Model-generated next_actions prose is NEVER executed. Only structured execution_plan is executable.
    3. Target paths (run_python_file, run_binary, read_file) must resolve strictly inside challenge boundaries.
    4. Tools must be explicitly registered in ALLOWED_ANALYSIS_TOOLS; arbitrary executables are rejected.
    5. Tool operands are strictly inspected: external paths (/etc/passwd, ../../) are rejected.
    6. Strict environment isolation (strips platform tokens, sessions, cookies, GitHub keys).
    7. Multi-action plans (action 1 -> action 2 -> action 3) execute deterministically with per-action timeouts.
    8. Evidence-based result verification (exit code 0 alone is INCONCLUSIVE without evidence).
    NOTE: restricted-local is NOT a full sandbox (a local Python script can still access host resources).
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
        return ActionPolicy.sanitize_environment(extra_vars)

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

        input_dir = Path(challenge_context.get("input_dir", work_dir.parent / "input")).resolve()
        if not input_dir.is_dir():
            input_dir = work_dir

        safe_env = self._build_safe_env(challenge_context.get("env_vars"))

        def run_single_action(action: ExecutionAction, ctx: Dict[str, Any]) -> Dict[str, Any]:
            kind = action.kind
            argv: List[str] = []

            if kind in ["run_solver", "run_python_file"]:
                target_script = ArtifactResolver.resolve_local(
                    action.path or "solve.py", input_dir, work_dir, require_exists=True
                )
                argv = ["python3", str(target_script)]
                if action.argv and len(action.argv) > 1:
                    clean_args = ArtifactResolver.translate_argv(action.argv[1:], input_dir, work_dir, in_container=False)
                    argv.extend([arg for arg in clean_args if not any(c in arg for c in [";", "&", "|", "`", "$"])])

            elif kind == "run_sage_file":
                if not shutil.which("sage"):
                    raise FileNotFoundError("SageMath executable ('sage') not installed on host PATH")
                target_script = ArtifactResolver.resolve_local(
                    action.path or "solve.sage", input_dir, work_dir, require_exists=True
                )
                argv = ["sage", str(target_script)]
                if action.argv and len(action.argv) > 1:
                    clean_args = ArtifactResolver.translate_argv(action.argv[1:], input_dir, work_dir, in_container=False)
                    argv.extend([arg for arg in clean_args if not any(c in arg for c in [";", "&", "|", "`", "$"])])

            elif kind == "run_binary":
                bin_target = action.path or (action.argv[0] if action.argv else None)
                target_bin = ArtifactResolver.resolve_local(bin_target, input_dir, work_dir, require_exists=True)
                argv = [str(target_bin)]
                if action.argv and len(action.argv) > 1:
                    clean_args = ArtifactResolver.translate_argv(action.argv[1:], input_dir, work_dir, in_container=False)
                    argv.extend(clean_args)

            elif kind == "read_file":
                read_target = action.path or (action.argv[0] if action.argv else None)
                target_file = ArtifactResolver.resolve_local(read_target, input_dir, work_dir, require_exists=True)
                argv = ["cat", str(target_file)]

            elif kind == "list_files":
                argv = ["ls", "-la"]

            elif kind == "analysis_tool":
                tool_name = action.tool or (action.argv[0] if action.argv else None)
                if not tool_name or tool_name not in ALLOWED_ANALYSIS_TOOLS:
                    raise PermissionError(f"Analysis tool '{tool_name}' is not in allowed registry: {sorted(ALLOWED_ANALYSIS_TOOLS)}")
                if not shutil.which(tool_name):
                    raise FileNotFoundError(f"Analysis tool '{tool_name}' not installed on host PATH")

                clean_argv = [tool_name]
                raw_args = action.argv[1:] if (action.argv and action.argv[0] == tool_name) else (action.argv or [])
                clean_argv.extend(ArtifactResolver.translate_argv(raw_args, input_dir, work_dir, in_container=False))
                argv = clean_argv

            else:
                raise ValueError(f"Unsupported execution action kind: '{kind}'")

            cmd_repr = " ".join(argv)
            console.print(f"[dim]⚡ [RestrictedExecutor] Executing (shell=False): {cmd_repr}[/dim]")

            proc = subprocess.run(
                argv,
                shell=False,
                cwd=str(work_dir),
                env=safe_env,
                capture_output=True,
                text=True,
                timeout=action.timeout or self.timeout,
            )
            return {
                "return_code": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "action_repr": cmd_repr,
            }

        return ExecutionRunner.run_plan(
            challenge_context=challenge_context,
            guidance=guidance,
            work_dir=work_dir,
            input_dir=input_dir,
            single_action_executor=run_single_action,
            flag_format_regex=self.flag_format_regex,
            default_timeout=self.timeout,
        )
