from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from ..downloaders.manager import DownloadManager
from ..models import CTFInfo
from ..platforms.registry import create_platform, detect_platform_type
from ..runtime.manager import RuntimeManager, sanitize_path_component

console = Console()

class PullService:
    """
    Synchronizes competition metadata from platform adapter.
    Adheres strictly to the Ephemeral Runtime Architecture:
    - Challenges remain in memory and cached in .runtime/<event-id>/event.json.
    - Does NOT write global challenges.json or copy .env files.
    - Default behavior is LAZY: does not create challenge directories or download attachments
      until an autonomous scheduler or user explicitly selects a challenge.
    - Preloading all challenges can be triggered explicitly via preload_all=True.
    """
    def __init__(
        self,
        url: Optional[str] = None,
        output_dir: Optional[Path] = None,
        session_cookie: Optional[str] = None,
        api_token: Optional[str] = None,
        platform_type: Optional[str] = None,
        download_attachments: bool = False,
        category: Optional[str] = None,
        preload_all: bool = False,
        runtime_manager: Optional[RuntimeManager] = None,
        event_id: Optional[str] = None,
        platform_url: Optional[str] = None,
    ):
        target_url = url or platform_url
        if not target_url:
            raise ValueError("Either url or platform_url must be provided.")
        self.url = target_url.rstrip("/")
        self.session_cookie = session_cookie
        self.api_token = api_token
        self.platform_type = platform_type or detect_platform_type(self.url, self.session_cookie)
        self.preload_all = preload_all
        # When preloading all, download attachments unless explicitly disabled
        self.download_attachments = download_attachments or preload_all
        self.category = category.strip() if category else None
        
        self.runtime_manager = runtime_manager or RuntimeManager()
        # Derive event_id from url host or provided id
        if event_id:
            self.event_id = sanitize_path_component(event_id)
        else:
            from urllib.parse import urlsplit
            host = urlsplit(self.url).netloc or "ctf_event"
            self.event_id = sanitize_path_component(host)

        self.platform = create_platform(
            platform_name=self.platform_type,
            url=self.url,
            session_cookie=self.session_cookie,
            api_token=self.api_token
        )
        self.downloader = DownloadManager(
            platform_url=self.url,
            session_cookie=self.session_cookie,
            api_token=self.api_token
        )

    def pull(self) -> CTFInfo:
        """Alias for execute() to ensure canonical compatibility."""
        return self.execute()


    def execute(self) -> CTFInfo:
        console.print(f"[bold cyan]⚡ Connecting to CTF Platform:[/bold cyan] {self.url}")
        console.print(f"[cyan]→ Platform Type:[/cyan] [bold green]{self.platform_type.upper()}[/bold green]")
        
        # 1. Authenticate
        if not self.platform.authenticate():
            console.print("[yellow]⚠️ Warning: Authentication failed or running in Guest mode...[/yellow]")
        else:
            console.print("[green]✔ Authenticated successfully![/green]")

        # 2. Fetch event info & challenge list in memory
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            t1 = progress.add_task("Fetching challenge list from platform...", total=None)
            ctf_info = self.platform.get_event_info()
            try:
                challenges = self.platform.list_challenges()
            except Exception:
                challenges = self.platform.fetch_challenges()

            if self.category:
                cat_lower = self.category.lower()
                challenges = [c for c in challenges if c.category and c.category.lower() == cat_lower]

            ctf_info.challenges = challenges
            progress.update(t1, completed=1)

        if self.category:
            console.print(f"[bold green]✔ Filtered {len(challenges)} challenge(s) in category [cyan]{self.category}[/cyan].[/bold green]")
        else:
            console.print(f"[bold green]✔ Found {len(challenges)} challenge(s).[/bold green]")

        # 3. Store event metadata into Ephemeral Runtime cache (.runtime/<event-id>/event.json)
        self.runtime_manager.start_event(self.event_id, ctf_info)
        console.print(f"[dim]⚡ Event metadata cached in runtime: .runtime/{self.event_id}/event.json[/dim]")

        # 4. Preload only if explicitly requested
        if self.preload_all:
            console.print("[cyan]📦 Explicit --all requested: pre-materializing all challenges...[/cyan]")
            for chall in challenges:
                dl_fn = None
                if self.download_attachments and chall.files:
                    dl_fn = lambda dest, c=chall: self.downloader.download_attachments(c.files, dest)
                self.runtime_manager.materialize_challenge(self.event_id, chall, download_fn=dl_fn)
            console.print("[green]✔ Pre-materialization complete.[/green]")
        else:
            console.print("[dim]⚡ Lazy mode active: Challenges will be materialized when selected.[/dim]")

        # 5. Render summary table
        table = Table(title=f"🎯 Challenge List — {ctf_info.title}", show_header=True, header_style="bold magenta")
        table.add_column("ID", style="dim", width=8)
        table.add_column("Category", style="cyan", width=12)
        table.add_column("Challenge Name", style="bold", width=30)
        table.add_column("Points", justify="right", width=8)
        table.add_column("Solves", justify="right", width=8)
        table.add_column("Dynamic Container", justify="center", width=18)

        for c in challenges:
            is_dc = "[green]Yes (Docker)[/green]" if c.is_dynamic_container else "[dim]No[/dim]"
            table.add_row(
                str(c.id),
                c.category,
                c.name,
                str(c.points),
                str(c.solves_count or 0),
                is_dc
            )
        console.print(table)
        return ctf_info
