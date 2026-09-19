import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional
from rich.console import Console

from ..models import AdvisorGuidance, ExecutionAction, ExecutionResult
from .evaluator import ExecutionResultEvaluator
from .restricted_executor import RestrictedLocalExecutor
from .artifacts import ArtifactResolver, ArtifactResolutionError
from .policy import (
    ActionPolicy,
    ExecutionPolicyError,
    SAFE_ENV_KEYS,
)
from .runner import ExecutionRunner

console = Console()

DEFAULT_CATEGORY_IMAGES = {
    "base": "python:3.11-slim",
    "pwn": "ghcr.io/danggphuc/ctf-pwn:latest",
    "web": "python:3.11-slim",
    "crypto": "python:3.11-slim",
    "crypto-sage": "sagemath/sagemath:latest",
    "rev": "python:3.11-slim",
    "forensics": "python:3.11-slim",
}


class ContainerExecutor:
    """
    Container-isolated executor using Docker or Podman.
    Security guarantees:
      - Mounts:
          input/ as READ-ONLY (:ro)
          work/ as READ-WRITE (:rw)
      - Hardening:
          --cap-drop ALL
          --security-opt no-new-privileges
          Resource quotas (--cpus=1, --memory=512m)
      - Network:
          Default is 'none'. 'bridge' only when remote service target is defined
          and network is explicitly permitted. NEVER 'host'.
      - Secret Isolation:
          Host environment credentials, tokens, cookies are NEVER passed into container.
      - Closed Execution:
          Output is captured and parsed directly. NEVER silently re-executes on host
          unless explicitly permitted via allow_local_fallback=True.
      - Multi-Action Execution:
          Executes multi-action plans sequentially (action 1 -> action 2 -> action 3)
          with per-action timeouts and unified ActionPolicy validation.
    """

    def __init__(
        self,
        flag_format_regex: str = r"FLAG\{[^\n\r\}]+\}",
        flag_format: Optional[str] = None,
        image: str = "python:3.11-slim",
        allow_network: bool = False,
        network_profile: str = "none",
        allow_local_fallback: bool = False,
        category_images: Optional[Dict[str, str]] = None,
    ):
        self.flag_format_regex = flag_format or flag_format_regex
        self.image = image
        self.category_images = category_images or DEFAULT_CATEGORY_IMAGES
        self.allow_network = allow_network
        self.network_profile = "bridge" if allow_network else network_profile
        self.allow_local_fallback = allow_local_fallback
        self.fallback = RestrictedLocalExecutor(flag_format_regex=self.flag_format_regex)
        self.engine = self._detect_engine()

    def _detect_engine(self) -> Optional[str]:
        for eng in ["docker", "podman"]:
            if shutil.which(eng):
                try:
                    res = subprocess.run([eng, "info"], capture_output=True, text=True, timeout=3)
                    if res.returncode == 0:
                        return eng
                except Exception:
                    pass
        return None

    def execute(self, challenge_context: Dict[str, Any], guidance: AdvisorGuidance) -> ExecutionResult:
        work_dir = Path(challenge_context.get("work_dir", ".")).resolve()
        input_dir = work_dir.parent / "input"
        iteration = challenge_context.get("iteration", 1)
        experiment_id = f"EXP-{iteration:03d}"

        # 1. Engine availability check
        if not self.engine:
            if self.allow_local_fallback:
                console.print("[yellow]⚠️ No container engine active. Delegating to RestrictedLocalExecutor (--allow-local-fallback is ON).[/yellow]")
                return self.fallback.execute(challenge_context, guidance)
            console.print("[bold red]❌ Container engine (docker/podman) is unavailable. Untrusted code will NOT be run on host by default.[/bold red]")
            return ExecutionResult(
                experiment_id=experiment_id,
                status="ERROR",
                return_code=-1,
                actions=["container_engine_check"],
                observed="Container engine unavailable and local host execution fallback is disabled (--allow-local-fallback required).",
                evidence=[],
                flag_candidates=[],
            )

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

        # 2. Network policy resolution
        # Default: 'none'. 'bridge' allowed only if remote service target is defined and requested
        has_remote = bool(challenge_context.get("connection_info") or challenge_context.get("host"))
        if has_remote and (self.allow_network or self.network_profile == "bridge"):
            net_mode = "bridge"
        else:
            net_mode = "none"

        cat = (challenge_context.get("category") or "base").lower()
        default_category_image = self.category_images.get(cat, self.image)

        # 3. Single action execution callback for ExecutionRunner
        def run_single_container_action(action: ExecutionAction, ctx: Dict[str, Any]) -> Dict[str, Any]:
            kind = action.kind
            selected_image = default_category_image
            sub_cmd: List[str] = []

            if kind in ["run_solver", "run_python_file"]:
                container_script = ArtifactResolver.resolve_container(
                    action.path or "solve.py", input_dir, work_dir
                )
                sub_cmd = ["python3", container_script]
                if action.argv and len(action.argv) > 1:
                    clean_args = ArtifactResolver.translate_argv(action.argv[1:], input_dir, work_dir, in_container=True)
                    sub_cmd.extend(clean_args)

            elif kind == "run_sage_file":
                selected_image = self.category_images.get("crypto-sage", "sagemath/sagemath:latest")
                container_script = ArtifactResolver.resolve_container(
                    action.path or "solve.sage", input_dir, work_dir
                )
                sub_cmd = ["sage", container_script]
                if action.argv and len(action.argv) > 1:
                    clean_args = ArtifactResolver.translate_argv(action.argv[1:], input_dir, work_dir, in_container=True)
                    sub_cmd.extend(clean_args)

            elif kind == "run_binary":
                bin_target = action.path or (action.argv[0] if action.argv else "vuln")
                container_bin = ArtifactResolver.resolve_container(bin_target, input_dir, work_dir)
                sub_cmd = [container_bin]
                if action.argv and len(action.argv) > 1:
                    clean_args = ArtifactResolver.translate_argv(action.argv[1:], input_dir, work_dir, in_container=True)
                    sub_cmd.extend(clean_args)

            elif kind == "read_file":
                read_target = action.path or (action.argv[0] if action.argv else "flag.txt")
                container_file = ArtifactResolver.resolve_container(read_target, input_dir, work_dir)
                sub_cmd = ["cat", container_file]

            elif kind == "list_files":
                sub_cmd = ["ls", "-la"]

            elif kind == "analysis_tool":
                tool_name = action.tool or (action.argv[0] if action.argv else "checksec")
                raw_args = action.argv[1:] if (action.argv and action.argv[0] == tool_name) else (action.argv or [])
                clean_args = ArtifactResolver.translate_argv(raw_args, input_dir, work_dir, in_container=True)
                sub_cmd = [tool_name, *clean_args]

            else:
                sub_cmd = ["python3", "solve.py"]

            # Assemble docker/podman command
            cmd = [
                self.engine, "run", "--rm",
                "--cpus=1", "--memory=512m",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                f"--network={net_mode}",
                "-v", f"{work_dir}:/work:rw",
                "-w", "/work",
            ]

            if input_dir.is_dir():
                cmd.extend(["-v", f"{input_dir}:/input:ro"])

            # Pass sanitized environment variables (no credentials)
            safe_env = ActionPolicy.sanitize_environment(ctx.get("env_vars"))
            for k, v in safe_env.items():
                if k not in SAFE_ENV_KEYS:
                    cmd.extend(["-e", f"{k}={v}"])

            cmd.extend([selected_image, *sub_cmd])

            action_repr = f"{self.engine}:{ ' '.join(sub_cmd) }"
            console.print(f"[cyan]🐳 [ContainerExecutor] Running action in {self.engine} (timeout={action.timeout}s): { ' '.join(sub_cmd) }[/cyan]")

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=action.timeout or 60,
            )

            return {
                "return_code": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "action_repr": action_repr,
            }

        try:
            return ExecutionRunner.run_plan(
                challenge_context=challenge_context,
                guidance=guidance,
                work_dir=work_dir,
                input_dir=input_dir,
                single_action_executor=run_single_container_action,
                flag_format_regex=self.flag_format_regex,
                default_timeout=60,
            )
        except Exception as e:
            if self.allow_local_fallback:
                console.print(f"[yellow]⚠️ Container execution failed: {e}. Falling back to RestrictedLocalExecutor (--allow-local-fallback is ON).[/yellow]")
                return self.fallback.execute(challenge_context, guidance)
            console.print(f"[bold red]❌ Container execution failed: {e}. Silently running on host is disabled.[/bold red]")
            return ExecutionResultEvaluator.build_result(
                experiment_id=experiment_id,
                return_code=-1,
                stdout="",
                stderr=str(e),
                actions_performed=["container_error"],
                work_dir=work_dir,
                guidance=guidance,
                flag_format_regex=self.flag_format_regex,
                error_message=f"Container execution failed: {e}",
            )
