import re
from pathlib import Path
from typing import Any, Optional
from rich.console import Console
from ..models import ContainerInfo
from ..platforms.registry import create_platform, detect_platform_type
from ..workspace.repo import WorkspaceRepo

console = Console()

class InstanceService:
    def __init__(
        self,
        workspace_dir: Path,
        platform_url: str,
        session_cookie: Optional[str] = None,
        api_token: Optional[str] = None,
        platform_type: Optional[str] = None
    ):
        self.workspace_dir = Path(workspace_dir).resolve()
        self.repo = WorkspaceRepo(self.workspace_dir)
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
            self._sync_container_to_files(challenge_id, info)
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

    def _sync_container_to_files(self, challenge_id: Any, info: ContainerInfo):
        """
        Tự động parse host:port và cập nhật thẳng vào solve.py và README.md.
        """
        chall_dir = self.repo.find_challenge_dir(challenge_id)
        if not chall_dir:
            console.print(f"[yellow]⚠️ Không tìm thấy thư mục của Challenge ID {challenge_id} để sync file.[/yellow]")
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

        # 1. Cập nhật solver/solve.py
        solve_file = chall_dir / "solver" / "solve.py"
        if solve_file.is_file():
            content = solve_file.read_text(encoding="utf-8")
            if host and port:
                content = re.sub(r'HOST\s*=\s*["\'][^"\']+["\']', f'HOST = "{host}"', content)
                content = re.sub(r'PORT\s*=\s*[0-9]+', f'PORT = {port}', content)
            if entry.startswith("http"):
                content = re.sub(r'TARGET_URL\s*=\s*["\'][^"\']+["\']', f'TARGET_URL = "{entry}"', content)
            solve_file.write_text(content, encoding="utf-8")
            console.print(f"[green]✔ Đã tự động cập nhật HOST:PORT vào [bold]{solve_file.relative_to(self.workspace_dir)}[/bold][/green]")

        # 2. Cập nhật challenge/README.md
        readme_file = chall_dir / "challenge" / "README.md"
        if readme_file.is_file():
            readme_text = readme_file.read_text(encoding="utf-8")
            conn_block = f"## 🔌 Connection / Target Service\n```bash\nnc {host} {port}\n```" if (host and port) else f"## 🔌 Connection / Target Service\n```bash\n{entry}\n```"
            if "## 🔌 Connection / Target Service" in readme_text:
                readme_text = re.sub(
                    r'## 🔌 Connection / Target Service[\s\S]*?```[\s\S]*?```',
                    conn_block,
                    readme_text,
                    count=1
                )
            else:
                readme_text = f"{conn_block}\n\n{readme_text}"
            readme_file.write_text(readme_text, encoding="utf-8")

        # 3. Cập nhật metadata.json
        meta = self.repo.read_challenge_metadata(chall_dir) or {}
        meta["connection_info"] = entry
        meta["instance_info"] = info.model_dump()
        self.repo.write_challenge_metadata(chall_dir, meta)
