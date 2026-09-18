from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table

from ..config import save_env_file
from ..downloaders.manager import DownloadManager
from ..models import CTFInfo
from ..platforms.registry import create_platform, detect_platform_type
from ..workspace.builder import WorkspaceBuilder, sanitize_name
from ..workspace.repo import WorkspaceRepo

console = Console()

class PullService:
    def __init__(
        self,
        url: str,
        output_dir: Path,
        session_cookie: Optional[str] = None,
        api_token: Optional[str] = None,
        platform_type: Optional[str] = None,
        download_attachments: bool = True,
        category: Optional[str] = None
    ):
        self.url = url.rstrip("/")
        self.output_dir = Path(output_dir).resolve()
        self.session_cookie = session_cookie
        self.api_token = api_token
        self.platform_type = platform_type or detect_platform_type(self.url, self.session_cookie)
        self.download_attachments = download_attachments
        self.category = category.strip() if category else None
        
        self.platform = create_platform(
            platform_name=self.platform_type,
            url=self.url,
            session_cookie=self.session_cookie,
            api_token=self.api_token
        )
        self.downloader = DownloadManager(
            session_cookie=self.session_cookie,
            api_token=self.api_token
        )
        self.repo = WorkspaceRepo(self.output_dir)

    def execute(self) -> CTFInfo:
        console.print(f"[bold cyan]⚡ Bắt đầu đồng bộ giải CTF từ:[/bold cyan] {self.url}")
        console.print(f"[cyan]→ Nền tảng:[/cyan] [bold green]{self.platform_type.upper()}[/bold green]")
        
        # 1. Kiểm tra xác thực
        if not self.platform.authenticate():
            console.print("[yellow]⚠️ Cảnh báo: Không thể xác thực hoặc chưa đăng nhập. Tiến hành crawl ở chế độ khách (Guest)...[/yellow]")
        else:
            console.print("[green]✔ Xác thực tài khoản thành công![/green]")

        # 2. Lấy thông tin giải & danh sách challenge
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            t1 = progress.add_task("Đang tải danh sách bài tập...", total=None)
            ctf_info = self.platform.fetch_ctf_info()
            try:
                # Một số platform hỗ trợ trực tiếp tham số category
                challenges = self.platform.fetch_challenges(category=self.category)
            except TypeError:
                challenges = self.platform.fetch_challenges()
                if self.category:
                    cat_lower = self.category.lower()
                    challenges = [c for c in challenges if c.category and c.category.lower() == cat_lower]

            ctf_info.challenges = challenges
            progress.update(t1, completed=1)

        if self.category:
            console.print(f"[bold green]✔ Đã lọc {len(challenges)} bài tập thuộc danh mục [cyan]{self.category}[/cyan].[/bold green]")
        else:
            console.print(f"[bold green]✔ Đã tìm thấy {len(challenges)} bài tập.[/bold green]")

        # 3. Tạo thư mục output & lưu .env tự động
        self.output_dir.mkdir(parents=True, exist_ok=True)
        flag_fmt = ctf_info.flag_format or r"^FLAG\{.+\}$"
        save_env_file(
            self.output_dir / ".env",
            {
                "PLATFORM_URL": self.url,
                "SESSION_COOKIE": self.session_cookie or "",
                "API_TOKEN": self.api_token or "",
                "FLAG_FORMAT": flag_fmt,
                "WORKSPACE_DIR": str(self.output_dir)
            }
        )
        console.print(f"[green]✔ Đã ném cấu hình vào [bold]{self.output_dir / '.env'}[/bold] cho Anti-IDE.[/green]")

        # 4. Dựng Workspace 4 tầng & tải đính kèm
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Đang dựng workspace 4 tầng...", total=len(challenges))
            for chall in challenges:
                progress.update(task, description=f"Đang dựng: [bold]{chall.name[:25]}[/bold]")
                downloaded_files = []
                if self.download_attachments and chall.files:
                    target_dl_dir = self.output_dir / ".downloads" / sanitize_name(chall.name)
                    downloaded_files = self.downloader.download_attachments(chall.files, target_dl_dir)
                
                WorkspaceBuilder.create_challenge_workspace(
                    workspace_root=self.output_dir,
                    challenge=chall,
                    downloaded_files=downloaded_files
                )
                progress.advance(task)

        # 5. Lưu challenges.json & SUMMARY.md
        self.repo.write_challenges(ctf_info.model_dump())
        WorkspaceBuilder.generate_summary(self.output_dir, ctf_info)
        console.print(f"[green]✔ Đã ghi [bold]{self.output_dir / 'challenges.json'}[/bold] và [bold]SUMMARY.md[/bold][/green]")

        # 6. Render bảng tóm tắt
        table = Table(title=f"🎯 Danh sách Challenge — {ctf_info.title}", show_header=True, header_style="bold magenta")
        table.add_column("ID", style="dim", width=6)
        table.add_column("Category", style="cyan", width=12)
        table.add_column("Challenge Name", style="bold", width=30)
        table.add_column("Points", justify="right", width=8)
        table.add_column("Solves", justify="right", width=8)
        table.add_column("Dynamic Container", justify="center", width=18)

        for c in challenges:
            is_dc = "[green]Có (Docker)[/green]" if c.is_dynamic_container else "[dim]Không[/dim]"
            table.add_row(
                str(c.id),
                c.category,
                c.name,
                str(c.points),
                str(c.solves_count or 0),
                is_dc
            )
        console.print(table)
        console.print(f"[bold green]✨ Hoàn tất! Workspace đã sẵn sàng tại: {self.output_dir}[/bold green]")
        return ctf_info
