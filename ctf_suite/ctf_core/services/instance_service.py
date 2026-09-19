import json
import re
from pathlib import Path
from typing import Any, Optional
from rich.console import Console

from ..models import ContainerInfo
from ..platforms.registry import create_platform, detect_platform_type
from ..runtime.manager import RuntimeManager

console = Console()

class InstanceService:
    def __init__(
        self,
        platform_url: str,
        session_cookie: Optional[str] = None,
        api_token: Optional[str] = None,
        platform_type: Optional[str] = None,
        runtime_manager: Optional[RuntimeManager] = None,
        event_id: Optional[str] = None,
        platform: Optional[Any] = None,
        workspace_dir: Optional[Path] = None,  # Kept for backward compatibility
    ):
        self.runtime_manager = runtime_manager or RuntimeManager()
        self.event_id = event_id or "default_event"
        
        if platform is not None:
            self.platform = platform
        else:
            p_type = platform_type or detect_platform_type(platform_url, session_cookie)
            self.platform = create_platform(
                platform_name=p_type,
                url=platform_url,
                session_cookie=session_cookie,
                api_token=api_token
            )

    def start(self, challenge_id: Any) -> ContainerInfo:
        console.print(f"[bold cyan]🚀 Đang khởi tạo container cho Challenge ID: {challenge_id}...[/bold cyan]")
        info = self.platform.start_instance(challenge_id)
        if info.status == "running":
            console.print(f"[bold green]✔ Container đã hoạt động![/bold green] Entry: [bold yellow]{info.entry}[/bold yellow]")
            self._sync_container_to_runtime(challenge_id, info)
        else:
            console.print(f"[bold red]❌ Khởi tạo thất bại:[/bold red] {info.message}")
        return info

    def stop(self, challenge_id: Any) -> bool:
        console.print(f"[yellow]🛑 Đang dừng container cho Challenge ID: {challenge_id}...[/yellow]")
        ok = self.platform.stop_instance(challenge_id)
        if ok:
            console.print(f"[green]✔ Đã dừng container ID {challenge_id} thành công.[/green]")
        else:
            console.print(f"[red]❌ Dừng container thất bại.[/red]")
        return ok

    def extend(self, challenge_id: Any) -> bool:
        console.print(f"[cyan]⏳ Đang gia hạn container cho Challenge ID: {challenge_id}...[/cyan]")
        ok = self.platform.extend_instance(challenge_id)
        if ok:
            console.print(f"[green]✔ Đã gia hạn thời gian container thành công![/green]")
        else:
            console.print(f"[red]❌ Gia hạn thất bại hoặc đã đạt giới hạn.[/red]")
        return ok

    def _sync_container_to_runtime(self, challenge_id: Any, info: ContainerInfo):
        """
        Cập nhật connection_info và instance_info vào state.json trong runtime challenge
        và tự động patch HOST:PORT vào work/solve.py nếu có.
        """
        cpath = self.runtime_manager.challenge_path(self.event_id, challenge_id)
        if not cpath.exists():
            console.print(f"[yellow]⚠️ Thư mục runtime của Challenge ID {challenge_id} chưa được materialize.[/yellow]")
            return

        entry = info.entry or ""
        host = info.host
        port = info.port

        if not host and entry and ":" in entry:
            parts = entry.split(":")
            host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                pass

        # 1. Cập nhật work/solve.py nếu có
        solve_file = cpath / "work" / "solve.py"
        if solve_file.is_file():
            content = solve_file.read_text(encoding="utf-8")
            if host and port:
                safe_host_literal = json.dumps(str(host))
                try:
                    safe_port_literal = int(port)
                except (ValueError, TypeError):
                    safe_port_literal = 1337
                if re.search(r'HOST\s*=\s*["\'][^"\']*["\']', content):
                    content = re.sub(r'HOST\s*=\s*["\'][^"\']*["\']', f'HOST = {safe_host_literal}', content)
                else:
                    content = f'HOST = {safe_host_literal}\n' + content
                if re.search(r'PORT\s*=\s*[0-9]+', content):
                    content = re.sub(r'PORT\s*=\s*[0-9]+', f'PORT = {safe_port_literal}', content)
                else:
                    content = f'PORT = {safe_port_literal}\n' + content
            if entry.startswith("http"):
                safe_url_literal = json.dumps(str(entry))
                if re.search(r'TARGET_URL\s*=\s*["\'][^"\']*["\']', content):
                    content = re.sub(r'TARGET_URL\s*=\s*["\'][^"\']*["\']', f'TARGET_URL = {safe_url_literal}', content)
                else:
                    content = f'TARGET_URL = {safe_url_literal}\n' + content
            solve_file.write_text(content, encoding="utf-8")
            console.print(f"[green]✔ Đã tự động cập nhật HOST:PORT vào work/solve.py[/green]")

        # 2. Cập nhật state.json
        state = self.runtime_manager.read_challenge_state(self.event_id, challenge_id) or {}
        state["connection_info"] = {
            "entry": entry,
            "host": host,
            "port": port,
        }
        state["instance_info"] = info.model_dump()
        self.runtime_manager.write_challenge_state(self.event_id, challenge_id, state)
