import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional
from rich.console import Console

from ..models import AdvisorGuidance, ExecutionAction, ExecutionResult
from .evaluator import ExecutionResultEvaluator
from .restricted_executor import RestrictedLocalExecutor

console = Console()

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
    """

    def __init__(
        self,
        flag_format_regex: str = r"FLAG\{[^\n\r\}]+\}",
        flag_format: Optional[str] = None,
        image: str = "python:3.11-slim",
        allow_network: bool = False,
        network_profile: str = "none",
        allow_local_fallback: bool = False,
    ):
        self.flag_format_regex = flag_format or flag_format_regex
        self.image = image
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

        # 3. Build container execution command
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

        # Strip host environment secrets - only pass safe non-sensitive vars if specified
        if "env_vars" in challenge_context and isinstance(challenge_context["env_vars"], dict):
            for k, v in challenge_context["env_vars"].items():
                if not any(bad in k.upper() for bad in ["TOKEN", "COOKIE", "SECRET", "AUTH", "PASS", "KEY"]):
                    cmd.extend(["-e", f"{k}={v}"])

        # Determine executable command inside container
        actions_performed: List[str] = []
        if guidance.execution_plan:
            first_action = guidance.execution_plan[0]
            if first_action.kind in ["run_solver", "run_python_file"]:
                script_name = first_action.path or "solve.py"
                target_script = (work_dir / script_name).resolve()
                if not target_script.is_relative_to(work_dir) or not target_script.is_file():
                    return ExecutionResult(
                        experiment_id=experiment_id,
                        status="ERROR",
                        return_code=-1,
                        actions=[f"resolve_script:{script_name}"],
                        observed=f"Target script {script_name} is outside work_dir or missing",
                        evidence=[],
                        flag_candidates=[],
                    )
                sub_cmd = ["python3", script_name]
                actions_performed.append(f"{self.engine}:python3 {script_name}")
            elif first_action.kind == "list_files":
                sub_cmd = ["ls", "-la"]
                actions_performed.append(f"{self.engine}:ls -la")
            else:
                sub_cmd = ["python3", "solve.py"]
                actions_performed.append(f"{self.engine}:python3 solve.py")
        else:
            solve_script = work_dir / "solve.py"
            if solve_script.is_file():
                sub_cmd = ["python3", "solve.py"]
                actions_performed.append(f"{self.engine}:python3 solve.py")
            else:
                sub_cmd = ["ls", "-la"]
                actions_performed.append(f"{self.engine}:ls -la")

        cmd.extend([self.image, *sub_cmd])

        console.print(f"[cyan]🐳 [ContainerExecutor] Running isolated execution in {self.engine} (network={net_mode})...[/cyan]")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=65)
            # P0: NEVER rerun on host! Build ExecutionResult directly from container output!
            return ExecutionResultEvaluator.build_result(
                experiment_id=experiment_id,
                return_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                actions_performed=actions_performed,
                work_dir=work_dir,
                guidance=guidance,
                flag_format_regex=self.flag_format_regex,
            )
        except subprocess.TimeoutExpired:
            return ExecutionResultEvaluator.build_result(
                experiment_id=experiment_id,
                return_code=-9,
                stdout="",
                stderr="Container timed out after 65s",
                actions_performed=actions_performed,
                work_dir=work_dir,
                guidance=guidance,
                flag_format_regex=self.flag_format_regex,
                timed_out=True,
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
                actions_performed=actions_performed,
                work_dir=work_dir,
                guidance=guidance,
                flag_format_regex=self.flag_format_regex,
                error_message=f"Container execution failed: {e}",
            )
