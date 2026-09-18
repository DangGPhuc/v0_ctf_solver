import os
import subprocess
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional
from rich.console import Console
from rich.table import Table

console = Console()

class ToolManager:
    def __init__(self, manifests_dir: Optional[Path] = None, tools_dir: Optional[Path] = None):
        self.manifests_dir = manifests_dir or (Path(__file__).resolve().parent / "manifests")
        self.tools_dir = tools_dir or (Path.home() / ".local" / "share" / "v0_ctf_solver" / "tools")
        self.tools_dir.mkdir(parents=True, exist_ok=True)

    def list_manifests(self) -> List[Dict[str, Any]]:
        manifests = []
        if not self.manifests_dir.is_dir():
            return manifests
        for ypath in sorted(self.manifests_dir.glob("*.yaml")):
            try:
                data = yaml.safe_load(ypath.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    data["manifest_path"] = str(ypath)
                    manifests.append(data)
            except Exception as e:
                console.print(f"[yellow]⚠️ Failed to load manifest {ypath.name}: {e}[/yellow]")
        return manifests

    def get_manifest(self, tool_id: str) -> Optional[Dict[str, Any]]:
        for m in self.list_manifests():
            if m.get("id") == tool_id:
                return m
        return None

    def is_installed(self, tool_id: str) -> bool:
        tdir = self.tools_dir / tool_id
        return tdir.is_dir()

    def check_health(self, tool_id: str) -> Dict[str, Any]:
        m = self.get_manifest(tool_id)
        if not m:
            return {"status": "error", "message": f"Unknown tool ID: {tool_id}"}

        healthcheck_cmd = m.get("healthcheck", {}).get("command")
        if not healthcheck_cmd:
            return {"status": "ok", "message": "No healthcheck command specified (assumed OK)"}

        try:
            res = subprocess.run(healthcheck_cmd, shell=True, capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                return {"status": "ok", "message": res.stdout.strip() or "Healthy"}
            else:
                return {"status": "unhealthy", "message": res.stderr.strip() or f"Exit code {res.returncode}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def install(self, tool_id: str) -> bool:
        m = self.get_manifest(tool_id)
        if not m:
            console.print(f"[bold red]❌ Tool ID '{tool_id}' not found in manifests.[/bold red]")
            return False

        tdir = self.tools_dir / tool_id
        tdir.mkdir(parents=True, exist_ok=True)
        console.print(f"[bold cyan]📦 Installing {m.get('name', tool_id)} v{m.get('version', '')} to {tdir}...[/bold cyan]")

        install_cfg = m.get("install", {})
        steps = install_cfg.get("steps", [])
        for step in steps:
            console.print(f"[dim]Running: {step}[/dim]")
            res = subprocess.run(step, shell=True, cwd=tdir, capture_output=True, text=True)
            if res.returncode != 0:
                console.print(f"[bold red]❌ Step failed: {res.stderr}[/bold red]")
                return False

        console.print(f"[bold green]✔ Successfully installed {tool_id}![/bold green]")
        return True
