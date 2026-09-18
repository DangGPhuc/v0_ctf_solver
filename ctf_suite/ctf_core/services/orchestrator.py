import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..config import load_config, find_env_file
from ..models import Challenge, SubmitResult
from ..workspace.repo import WorkspaceRepo
from .pull_service import PullService
from .submit_service import SubmitService
from .advisor_service import AdvisorService
from .chatgpt_service import ChatGPTService

console = Console()

class ChallengeOrchestrator:
    """
    Orchestrator điều phối chu trình giải tự động khép kín (Closed-Loop Autonomous Solver):
    Pull/Crawl (theo Category) 
      → Dựng Workspace 4 tầng & Sync reverse-skill
      → Triage & Khởi tạo Advisor (L0-L3 context)
      → Consult ChatGPT Web trên Firefox
      → Nhận hướng đi (Guidance) cho Anti-IDE / reverse-skill thực thi
      → Kiểm tra và nộp flag tức thì (Strict validation + deduplication)
      → Nếu chưa ra flag: Report evidence và consult vòng 2 (vòng lặp cho đến khi ra cờ)
      → Chuyển sang challenge chưa giải tiếp theo trong category
      → Khi hết category: Chờ wave mới hoặc thông báo hoàn tất.
    """
    def __init__(
        self,
        workspace_dir: Path,
        category: Optional[str] = None,
        platform_url: Optional[str] = None,
        session_cookie: Optional[str] = None,
        api_token: Optional[str] = None,
        flag_format: Optional[str] = None,
        max_iterations_per_chall: int = 5,
        reverse_skill_dir: Optional[Path] = None
    ):
        self.workspace_dir = Path(workspace_dir).resolve()
        self.category = category.strip() if category else None
        
        cfg = load_config(self.workspace_dir)
        self.platform_url = platform_url or cfg.platform_url
        self.session_cookie = session_cookie or cfg.session_cookie
        self.api_token = api_token or cfg.api_token
        self.flag_format = flag_format or cfg.flag_format or r"^FLAG\{.+\}$"
        self.max_iterations = max_iterations_per_chall
        
        self.reverse_skill_dir = (
            Path(reverse_skill_dir).resolve()
            if reverse_skill_dir
            else self.workspace_dir.parent / "reverse-skill"
        )
        
        self.repo = WorkspaceRepo(self.workspace_dir)
        self.submitter = SubmitService(
            workspace_dir=self.workspace_dir,
            platform_url=self.platform_url,
            session_cookie=self.session_cookie,
            api_token=self.api_token,
            flag_format=self.flag_format
        )
        self.advisor = AdvisorService(
            workspace_dir=self.workspace_dir,
            reverse_skill_dir=self.reverse_skill_dir
        )
        self.chatgpt = ChatGPTService(
            workspace_dir=self.workspace_dir,
            reverse_skill_dir=self.reverse_skill_dir
        )

    def sync_challenges(self, download_attachments: bool = True) -> List[Dict[str, Any]]:
        """Đồng bộ bài tập từ platform về workspace, lọc theo category."""
        if not self.platform_url:
            console.print("[yellow]⚠️ Chưa có PLATFORM_URL, sử dụng danh sách challenge hiện có trong workspace.[/yellow]")
            return self._get_unsolved_challenges()

        puller = PullService(
            url=self.platform_url,
            output_dir=self.workspace_dir,
            session_cookie=self.session_cookie,
            api_token=self.api_token,
            download_attachments=download_attachments,
            category=self.category
        )
        puller.execute()
        return self._get_unsolved_challenges()

    def _get_unsolved_challenges(self) -> List[Dict[str, Any]]:
        """Lấy danh sách các challenge chưa được giải trong workspace (có lọc theo category)."""
        unsolved: List[Dict[str, Any]] = []
        target_cat = self.category.lower() if self.category else None

        for cdir in self.repo.iter_challenge_dirs():
            meta = self.repo.read_challenge_metadata(cdir)
            if not meta:
                continue

            if meta.get("solved_by_me") is True:
                continue

            chall_cat = (meta.get("category") or "Misc").lower()
            if target_cat and chall_cat != target_cat:
                continue

            unsolved.append({
                "id": str(meta.get("id")),
                "name": meta.get("name", cdir.name),
                "category": meta.get("category", "Misc"),
                "points": meta.get("points", 0),
                "dir": cdir,
                "meta": meta
            })

        # Sắp xếp theo thứ tự điểm tăng dần để giải các bài dễ trước
        unsolved.sort(key=lambda x: int(x.get("points") or 0))
        return unsolved

    def check_flag_candidate(self, chall_dir: Path) -> Optional[str]:
        """Kiểm tra sự xuất hiện của flag hợp lệ trong solver/flag.txt hoặc challenge/flag.txt."""
        candidates = [
            chall_dir / "solver" / "flag.txt",
            chall_dir / "challenge" / "flag.txt",
            chall_dir / "flag.txt"
        ]
        for p in candidates:
            if p.is_file():
                try:
                    content = p.read_text(encoding="utf-8").strip()
                    if content and self.submitter.validate_format(content):
                        return content
                except Exception:
                    pass
        return None

    def execute_challenge_cycle(self, chall_info: Dict[str, Any]) -> bool:
        """
        Thực hiện chu trình khép kín cho một Challenge:
        1. Khởi tạo State & Triage
        2. Tham vấn ChatGPT Web qua Firefox
        3. Thu thập kết quả & phát hiện flag
        4. Nộp flag tức thì nếu phát hiện
        5. Lặp lại qua các vòng phản hồi nếu chưa có flag
        """
        cid = chall_info["id"]
        cname = chall_info["name"]
        cat = chall_info["category"]
        cdir = chall_info["dir"]

        console.print(Panel(
            f"[bold cyan]🎯 BẮT ĐẦU XỬ LÝ CHALLENGE:[/bold cyan] [bold yellow]{cname}[/bold yellow] (ID: {cid})\n"
            f"Danh mục  : [bold green]{cat}[/bold green]\n"
            f"Điểm số   : [magenta]{chall_info['points']}[/magenta]\n"
            f"Thư mục   : [dim]{cdir}[/dim]",
            title="[bold green]⚡ AUTONOMOUS SOLVER CYCLE[/bold green]"
        ))

        # Bước 1: Khởi tạo .advisor/ và đồng bộ reverse-skill
        self.advisor.init_challenge_advisor(cid)
        try:
            self.chatgpt.prepare_triage_prompt(cid)
        except Exception as e:
            console.print(f"[yellow]⚠️ Triage prompt warning: {e}[/yellow]")

        # Kiểm tra nhanh xem đã có flag từ trước chưa
        initial_flag = self.check_flag_candidate(cdir)
        if initial_flag:
            console.print(f"[bold green]🎯 Đã có sẵn Flag hợp lệ trong workspace: {initial_flag}[/bold green]")
            res = self.submitter.submit(cid, initial_flag, strict=True)
            if res.verdict in ["correct", "already_solved"]:
                return True

        # Bước 2: Vòng lặp Consult & Solve
        for iteration in range(1, self.max_iterations + 1):
            console.print(f"\n[bold magenta]─── [VÒNG {iteration}/{self.max_iterations}] THAM VẤN CỐ VẤN CHIẾN LƯỢC (CHATGPT WEB) ───[/bold magenta]")
            
            # Gửi tham vấn sang ChatGPT Web (sẽ copy vào clipboard và mở tab Firefox)
            consult_res = self.advisor.consult(cid)
            guidance_file = consult_res.get("guidance_file")
            
            console.print(Panel(
                f"[bold cyan]1.[/bold cyan] Đã copy Prompt 4 tầng vào Clipboard và mở Firefox tới ChatGPT Web.\n"
                f"[bold cyan]2.[/bold cyan] Executor (Anti-IDE / OpenCode) hãy đọc guidance tại: [bold yellow]{guidance_file}[/bold yellow]\n"
                f"[bold cyan]3.[/bold cyan] Chạy solver tại: [bold green]{cdir / 'solver' / 'solve.py'}[/bold green]\n"
                f"[bold cyan]4.[/bold cyan] Khi solver xuất flag, ghi vào [bold yellow]{cdir / 'solver' / 'flag.txt'}[/bold yellow]",
                title="[bold yellow]👉 HƯỚNG DẪN THỰC THI CHO AGENT[/bold yellow]"
            ))

            # Kiểm tra flag candidate sau khi hoàn tất hướng đi
            flag = self.check_flag_candidate(cdir)
            if flag:
                console.print(f"[bold green]🎯 Phát hiện flag mới sau vòng {iteration}: {flag}[/bold green]")
                sub_res = self.submitter.submit(cid, flag, strict=True)
                if sub_res.verdict in ["correct", "already_solved"]:
                    console.print(f"[bold green]✔ Challenge {cname} ĐÃ ĐƯỢC GIẢI THÀNH CÔNG VÀ ĂN ĐIỂM![/bold green]")
                    return True

            # Nếu chưa có flag, kiểm tra xem metadata đã đánh dấu solved chưa
            current_meta = self.repo.read_challenge_metadata(cdir) or {}
            if current_meta.get("solved_by_me"):
                return True

        console.print(f"[yellow]⏳ Challenge {cname} đã đạt giới hạn {self.max_iterations} vòng thử nghiệm. Tạm thời chuyển sang bài tiếp theo để tối ưu điểm số.[/yellow]")
        return False

    def run_tournament_loop(self, auto_wait_waves: bool = True, poll_interval: int = 45):
        """
        Chạy toàn bộ quy trình thi đấu cho Category được chỉ định:
        - Quét danh sách bài chưa giải trong Category
        - Giải tuần tự từng bài (từ dễ đến khó)
        - Khi xong 1 bài -> nộp flag tức thì -> chuyển sang bài tiếp theo
        - Khi giải hết Category -> tự động poll chờ wave mới (nếu bật auto_wait_waves).
        """
        cat_display = self.category.upper() if self.category else "TẤT CẢ DANH MỤC"
        console.print(Panel(
            f"[bold cyan]🚀 KHỞI ĐỘNG VÒNG LẶP THI ĐẤU TOURNAMENT ORCHESTRATOR[/bold cyan]\n\n"
            f"🎯 Mục tiêu Danh mục : [bold green]{cat_display}[/bold green]\n"
            f"📁 Workspace         : [green]{self.workspace_dir}[/green]\n"
            f"🌐 Platform URL      : [yellow]{self.platform_url or 'Chưa cấu hình'}[/yellow]\n"
            f"🔄 Chờ Wave Mới      : [cyan]{'Bật (Tự động poll)' if auto_wait_waves else 'Tắt'}[/cyan]",
            title="[bold green]⚡ CTF TOURNAMENT SOLVER[/bold green]"
        ))

        while True:
            # 1. Đồng bộ và lọc challenge
            unsolved = self.sync_challenges(download_attachments=True)

            if not unsolved:
                console.print(f"\n[bold green]🎉 XIN CHÚC MỪNG! Toàn bộ challenge thuộc danh mục [{cat_display}] đã được giải quyết![/bold green]")
                if not auto_wait_waves:
                    break

                console.print(f"[dim]⏳ Đang chờ wave challenge mới từ ban tổ chức... Kiểm tra lại sau {poll_interval}s...[/dim]")
                time.sleep(poll_interval)
                continue

            console.print(f"\n[bold cyan]📋 Tìm thấy {len(unsolved)} bài tập chưa giải thuộc danh mục [{cat_display}]:[/bold cyan]")
            for idx, c in enumerate(unsolved, start=1):
                console.print(f"  {idx}. [bold]{c['name']}[/bold] ({c['points']} pts) [dim]ID: {c['id']}[/dim]")

            # 2. Giải từng challenge theo thứ tự ưu tiên
            for c in unsolved:
                solved = self.execute_challenge_cycle(c)
                if solved:
                    # Quét toàn bộ workspace để nộp vét cờ phụ nếu có
                    self.submitter.auto_scan_and_submit()
                    console.print(f"[bold green]✔ Đã hoàn tất bài '{c['name']}'. Chuyển ngay sang bài tiếp theo![/bold green]\n")
                else:
                    console.print(f"[yellow]⏩ Bỏ qua tạm thời '{c['name']}' để thử thách bài tiếp theo.[/yellow]\n")

            if not auto_wait_waves:
                break
            
            time.sleep(10)
