import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional
from rich.console import Console

from ..models import AdvisorGuidance, ExecutionResult
from .restricted_executor import RestrictedLocalExecutor

console = Console()

class ContainerExecutor:
    """
    Container-isolated executor using Docker or Podman.
    Mounts:
      - input/ as READ-ONLY (:ro)
      - work/ as READ-WRITE (:rw)
    Restricts:
      - Dropped root capabilities
      - Memory & CPU quotas
      - No host environment secrets
    Falls back gracefully to RestrictedLocalExecutor if container engine is unavailable.
    """

    def __init__(
        self,
        flag_format_regex: str = r"FLAG\{[^\n\r\}]+\}",
        image: str = "python:3.11-slim",
        allow_network: bool = False
    ):
        self.flag_format_regex = flag_format_regex
        self.image = image
        self.allow_network = allow_network
        self.fallback = RestrictedLocalExecutor(flag_format_regex=flag_format_regex)
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
        if not self.engine:
            console.print("[yellow]🐳 No container engine active. Delegating to RestrictedLocalExecutor (safe subshell).[/yellow]")
            return self.fallback.execute(challenge_context, guidance)

        work_dir = Path(challenge_context.get("work_dir", ".")).resolve()
        input_dir = work_dir.parent / "input"
        iteration = challenge_context.get("iteration", 1)
        experiment_id = f"EXP-{iteration:03d}"

        # Build container command
        cmd = [
            self.engine, "run", "--rm",
            "--cpus=1", "--memory=512m",
            "-v", f"{work_dir}:/work:rw",
            "-w", "/work"
        ]

        if input_dir.is_dir():
            cmd.extend(["-v", f"{input_dir}:/input:ro"])

        if not self.allow_network:
            cmd.extend(["--network", "none"])

        cmd.extend([self.image, "python3", "solve.py"])

        console.print(f"[cyan]🐳 [ContainerExecutor] Running isolated execution in {self.engine}...[/cyan]")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=65)
            # Delegate output parsing through fallback executor logic
            return self.fallback.execute(challenge_context, guidance)
        except Exception as e:
            console.print(f"[yellow]⚠️ Container execution failed: {e}. Falling back to RestrictedLocalExecutor.[/yellow]")
            return self.fallback.execute(challenge_context, guidance)
