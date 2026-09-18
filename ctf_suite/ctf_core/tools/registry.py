import json
import os
import shlex
import shutil
import subprocess
import yaml
from datetime import datetime, timezone
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
        """
        Determines whether tool is installed by checking for a valid .installed.json marker.
        Merely having a directory present is NOT considered installed.
        """
        tdir = self.tools_dir / tool_id
        marker = tdir / ".installed.json"
        if not marker.is_file():
            return False
        try:
            data = json.loads(marker.read_text(encoding="utf-8"))
            return bool(data.get("healthcheck_passed"))
        except Exception:
            return False

    def check_health(self, tool_id: str) -> Dict[str, Any]:
        m = self.get_manifest(tool_id)
        if not m:
            return {"status": "error", "message": f"Unknown tool ID: {tool_id}"}

        healthcheck_cmd = m.get("healthcheck", {}).get("command")
        if not healthcheck_cmd:
            return {"status": "ok", "message": "No healthcheck command specified (assumed OK)"}

        try:
            # Use argv execution when possible
            args = shlex.split(healthcheck_cmd)
            res = subprocess.run(args, capture_output=True, text=True, timeout=10)
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

        # 1. Handle source checkout (git clone/fetch with pinned ref)
        source = m.get("source", {})
        source_type = source.get("type")
        source_url = source.get("url")
        source_ref = str(source.get("ref", "main"))

        if source_type == "git" and source_url:
            console.print(f"[dim]Cloning / fetching pinned ref '{source_ref}' from {source_url}...[/dim]")
            git_bin = shutil.which("git")
            if not git_bin:
                console.print("[bold red]❌ git executable not found on PATH[/bold red]")
                return False

            git_dir = tdir / ".git"
            if git_dir.is_dir():
                fetch_res = subprocess.run([git_bin, "fetch", "origin", source_ref], cwd=tdir, capture_output=True, text=True)
                checkout_res = subprocess.run([git_bin, "checkout", source_ref], cwd=tdir, capture_output=True, text=True)
                if checkout_res.returncode != 0:
                    console.print(f"[bold red]❌ git checkout failed: {checkout_res.stderr}[/bold red]")
                    return False
            else:
                clone_res = subprocess.run(
                    [git_bin, "clone", "--branch", source_ref, "--depth", "1", source_url, str(tdir)],
                    capture_output=True,
                    text=True
                )
                if clone_res.returncode != 0:
                    console.print(f"[bold red]❌ git clone failed: {clone_res.stderr}[/bold red]")
                    return False

        # 2. Run installation steps using argv lists
        install_cfg = m.get("install", {})
        steps = install_cfg.get("steps", [])
        for step in steps:
            console.print(f"[dim]Running: {step}[/dim]")
            args = shlex.split(step)
            res = subprocess.run(args, cwd=tdir, capture_output=True, text=True)
            if res.returncode != 0:
                console.print(f"[bold red]❌ Step failed: {res.stderr}[/bold red]")
                return False

        # 3. Run healthcheck
        h_res = self.check_health(tool_id)
        passed = (h_res.get("status") == "ok")

        # 4. Write .installed.json marker
        marker_data = {
            "source": source_url or "local",
            "ref": source_ref if source_type == "git" else "",
            "installed_at": datetime.now(timezone.utc).isoformat(),
            "healthcheck_passed": passed,
            "healthcheck_message": h_res.get("message", ""),
        }
        marker_file = tdir / ".installed.json"
        marker_file.write_text(json.dumps(marker_data, indent=2), encoding="utf-8")

        if passed:
            console.print(f"[bold green]✔ Successfully installed and verified {tool_id}![/bold green]")
            return True
        else:
            console.print(f"[bold red]⚠️ Installation completed but healthcheck failed: {h_res.get('message')}[/bold red]")
            return False
