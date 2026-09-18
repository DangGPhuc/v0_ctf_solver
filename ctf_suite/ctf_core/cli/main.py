import os
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from ..config import load_config, save_env_file, find_env_file
from ..models import Challenge
from ..platforms.registry import create_platform, detect_platform_type
from ..runtime.manager import RuntimeManager
from ..meta.knowledge_compiler import KnowledgeCompiler, KnowledgeRetriever
from ..services.pull_service import PullService
from ..services.instance_service import InstanceService
from ..services.submit_service import SubmitService
from ..services.chatgpt_service import ChatGPTService
from ..services.advisor_service import AdvisorService
from ..services.orchestrator import ChallengeOrchestrator
from ..workspace.repo import WorkspaceRepo

app = typer.Typer(
    name="ctf",
    help="⚡ CTF Anti-IDE Suite — Autonomous CTF Lifecycle & Solving Tool for Anti-IDE",
    add_completion=False,
    no_args_is_help=True
)
instance_app = typer.Typer(help="🐳 Quản lý dynamic container (start, stop, extend)")
env_app = typer.Typer(help="⚙ Quản lý cấu hình xác thực tệp .env")
chatgpt_app = typer.Typer(help="🤖 Tích hợp ChatGPT Web trên Firefox để phân tích đề bài")
advisor_app = typer.Typer(help="🧠 Strategic Advisor Multi-Agent Bridge (Anti-IDE/OpenCode ↔ ChatGPT Web via Oracle/PAL)")
meta_app = typer.Typer(help="🧬 Dream-RSI Meta-Layer: Discovery Trees, Policies, Offline Replay & Declarative Memory")
prompt_app = typer.Typer(help="📝 Prompt Master Engine: Contract Compiling, Linting & State Capsules")
cleanup_app = typer.Typer(help="🧹 Quản lý dọn dẹp runtime tạm thời (challenge, event, all)")
knowledge_app = typer.Typer(help="📚 Quản lý Thẻ Tri Thức (Knowledge Cards & Migrations)")

app.add_typer(instance_app, name="instance")
app.add_typer(env_app, name="env")
app.add_typer(chatgpt_app, name="chatgpt")
app.add_typer(advisor_app, name="advisor")
app.add_typer(meta_app, name="meta")
app.add_typer(prompt_app, name="prompt")
app.add_typer(cleanup_app, name="cleanup")
app.add_typer(knowledge_app, name="knowledge")

console = Console()

def _resolve_workspace(workspace: Optional[Path]) -> Path:
    if workspace:
        return workspace.resolve()
    cfg = load_config()
    if cfg.workspace_dir:
        p = Path(cfg.workspace_dir).resolve()
        if p.is_dir():
            return p
    found_env = find_env_file()
    if found_env:
        cand = found_env.parent / "CTF_Workspace"
        if cand.is_dir():
            return cand.resolve()
        return found_env.parent.resolve()
    cand = Path.cwd() / "CTF_Workspace"
    if cand.is_dir():
        return cand.resolve()
    return Path.cwd().resolve()

@app.command(name="list")
def list_challenges_cmd(
    category: Optional[str] = typer.Option(None, "--category", "-C", help="Lọc theo category"),
    url: Optional[str] = typer.Option(None, "--url", "-u", help="Platform URL"),
    cookie: Optional[str] = typer.Option(None, "--cookie", "-c", help="Session cookie"),
    token: Optional[str] = typer.Option(None, "--token", "-t", help="API token"),
):
    """
    Xem danh sách challenge trực tiếp từ platform (không tải tệp đính kèm hay tạo thư mục).
    """
    cfg = load_config()
    final_url = url or cfg.platform_url
    if not final_url:
        console.print("[bold red]❌ Lỗi: Chưa cung cấp URL giải đấu! Dùng -u <URL> hoặc ghi vào .env[/bold red]")
        raise typer.Exit(code=1)
    
    p_type = detect_platform_type(final_url, cookie or cfg.session_cookie)
    platform = create_platform(
        platform_name=p_type,
        url=final_url,
        session_cookie=cookie or cfg.session_cookie,
        api_token=token or cfg.api_token
    )
    if not platform.authenticate():
        console.print("[yellow]⚠️ Warning: Không thể xác thực tài khoản (chế độ Guest)...[/yellow]")
    
    try:
        challs = platform.list_challenges()
    except Exception:
        challs = platform.fetch_challenges()

    if category:
        cat_lower = category.lower().strip()
        challs = [c for c in challs if c.category and c.category.lower() == cat_lower]

    table = Table(title=f"🎯 Challenge List — {final_url}", show_header=True, header_style="bold magenta")
    table.add_column("ID", style="dim", width=8)
    table.add_column("Category", style="cyan", width=12)
    table.add_column("Challenge Name", style="bold", width=30)
    table.add_column("Points", justify="right", width=8)
    table.add_column("Solves", justify="right", width=8)
    table.add_column("Status", justify="center", width=12)

    for c in challs:
        st = "[bold green]✔ Solved[/bold green]" if c.solved_by_me else "[dim]Unsolved[/dim]"
        table.add_row(str(c.id), c.category, c.name, str(c.points), str(c.solves_count or 0), st)
    console.print(table)

@app.command(name="pull")
def pull(
    url: Optional[str] = typer.Option(None, "--url", "-u", help="URL của giải đấu (nếu để trống sẽ đọc từ .env)"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Thư mục xuất workspace"),
    cookie: Optional[str] = typer.Option(None, "--cookie", "-c", help="Session cookie"),
    token: Optional[str] = typer.Option(None, "--token", "-t", help="API token"),
    platform: Optional[str] = typer.Option(None, "--platform", "-p", help="ctfd hoặc gzctf hoặc cyberhx (tự nhận diện nếu bỏ qua)"),
    category: Optional[str] = typer.Option(None, "--category", "-C", help="Chỉ tải các challenge thuộc danh mục này (vd: Web, Pwn, Rev, Crypto, Forensics)"),
    no_downloads: bool = typer.Option(False, "--no-downloads", help="Bỏ qua việc tải tệp đính kèm")
):
    """
    Tải đề bài, tệp đính kèm và khởi tạo Workspace 4 tầng (có hỗ trợ lọc theo Category).
    """
    cfg = load_config(output)
    final_url = url or cfg.platform_url
    if not final_url:
        console.print("[bold red]❌ Lỗi: Chưa cung cấp URL giải đấu! Dùng -u <URL> hoặc ghi vào .env[/bold red]")
        raise typer.Exit(code=1)

    final_cookie = cookie or cfg.session_cookie
    final_token = token or cfg.api_token
    final_output = output or (Path.cwd() / "CTF_Workspace")

    service = PullService(
        url=final_url,
        output_dir=final_output,
        session_cookie=final_cookie,
        api_token=final_token,
        platform_type=platform,
        download_attachments=not no_downloads,
        category=category
    )
    service.execute()

@app.command(name="auto")
def auto_pipeline(
    url: Optional[str] = typer.Option(None, "--url", "-u", help="URL giải đấu (nếu để trống đọc từ .env)"),
    cookie: Optional[str] = typer.Option(None, "--cookie", "-c", help="Session cookie"),
    token: Optional[str] = typer.Option(None, "--token", "-t", help="API token"),
    category: Optional[str] = typer.Option(None, "--category", "-C", help="Giới hạn giải các challenge thuộc danh mục này (vd: Web, Pwn...)"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Thư mục workspace"),
    closed_loop: bool = typer.Option(True, "--closed-loop/--setup-only", help="Kích hoạt vòng lặp giải khép kín tự động (Triage -> Advisor -> Solver -> Submit)"),
    wait_waves: bool = typer.Option(False, "--wait-waves/--no-wait-waves", help="Tự động chờ và quét wave mới khi giải hết category"),
    no_downloads: bool = typer.Option(False, "--no-downloads", help="Bỏ qua việc tải trước toàn bộ tệp đính kèm lớn")
):
    """
    Quy trình tự động hóa khép kín hoàn chỉnh (Closed-Loop Autonomous Solver):
    1. Đăng nhập & crawl đề bài (theo Category được chọn)
    2. Dựng workspace 4 tầng & đồng bộ sang reverse-skill
    3. Tự động triage & consult ChatGPT Web trên Firefox
    4. Anti-IDE / OpenCode thực thi giải bài & báo cáo lại khi chưa có cờ
    5. Nộp flag tức thì (strict validation + dedup) và chuyển sang bài tiếp theo!
    """
    cfg = load_config(output)
    final_url = url or cfg.platform_url
    if not final_url:
        console.print("[bold red]❌ Lỗi: Vui lòng cung cấp URL giải đấu qua -u <URL> hoặc tệp .env![/bold red]")
        raise typer.Exit(code=1)

    final_cookie = cookie or cfg.session_cookie
    final_token = token or cfg.api_token
    final_output = output or (Path.cwd() / "CTF_Workspace")

    if closed_loop:
        orchestrator = ChallengeOrchestrator(
            workspace_dir=final_output,
            category=category,
            platform_url=final_url,
            session_cookie=final_cookie,
            api_token=final_token
        )
        orchestrator.run_tournament_loop(auto_wait_waves=wait_waves)
    else:
        # Chế độ setup-only tương thích ngược
        service = PullService(
            url=final_url,
            output_dir=final_output,
            session_cookie=final_cookie,
            api_token=final_token,
            download_attachments=not no_downloads,
            category=category
        )
        ctf_info = service.execute()
        if ctf_info.challenges:
            cg_service = ChatGPTService(workspace_dir=final_output)
            for c in ctf_info.challenges:
                try:
                    cg_service.prepare_triage_prompt(c.id)
                except Exception:
                    pass

@app.command(name="solve")
def solve(
    challenge_id: Optional[str] = typer.Argument(None, help="ID của một bài tập cụ thể cần giải"),
    category: Optional[str] = typer.Option(None, "--category", "-C", help="Danh mục bài tập cần giải (vd: Web, Pwn, Rev, Crypto, Forensics)"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w", help="Thư mục workspace"),
    wait_waves: bool = typer.Option(False, "--wait-waves/--no-wait-waves", help="Tự động chờ wave mới khi giải hết category")
):
    """
    Chạy bộ điều phối giải tự động (Challenge Orchestrator) cho 1 bài cụ thể hoặc Category.
    """
    ws_dir = _resolve_workspace(workspace)
    cfg = load_config(ws_dir)
    orchestrator = ChallengeOrchestrator(
        workspace_dir=ws_dir,
        category=category,
        platform_url=cfg.platform_url,
        session_cookie=cfg.session_cookie,
        api_token=cfg.api_token,
    )
    if challenge_id:
        chall = None
        if orchestrator.platform:
            chall = orchestrator.platform.get_challenge(challenge_id)
        if not chall:
            chall = Challenge(id=challenge_id, name=f"chall_{challenge_id}", category=category or "Misc")
        orchestrator.execute_challenge_cycle({
            "id": str(challenge_id),
            "name": chall.name,
            "category": chall.category,
            "points": chall.points,
            "challenge": chall,
        })
    else:
        orchestrator.run_tournament_loop(auto_wait_waves=wait_waves)

@app.command(name="status")
def status(
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w", help="Đường dẫn thư mục workspace")
):
    """
    Xem trạng thái runtime hiện tại và tiến độ giải trong workspace.
    """
    rt = RuntimeManager()
    events = rt.list_events()
    if events:
        console.print(f"[bold cyan]⚡ Active CTF Runtime Events:[/bold cyan] {', '.join(events)}")
        for eid in events:
            challs = rt.list_materialized_challenges(eid)
            einfo = rt.get_event_info(eid) or {}
            title = einfo.get("title", f"Event {eid}")
            solved = sum(1 for c in challs if c.get("solved_by_me"))
            total = len(challs)
            console.print(Panel(
                f"[bold green]Event: {title}[/bold green] (ID: {eid})\n"
                f"Materialized challenges: {total} | Solved: {solved}",
                title=f"[bold yellow]Event {eid}[/bold yellow]",
                border_style="cyan"
            ))
            if challs:
                table = Table(show_header=True, header_style="bold magenta")
                table.add_column("ID", width=8)
                table.add_column("Category", width=12)
                table.add_column("Name", width=30)
                table.add_column("Points", justify="right", width=8)
                table.add_column("Status", justify="center", width=14)
                for c in challs:
                    st = "[bold green]✔ Solved[/bold green]" if c.get("solved_by_me") else "[dim]⏳ In Progress[/dim]"
                    table.add_row(str(c.get("challenge_id")), c.get("category", "Misc"), c.get("name", ""), str(c.get("points", 0)), st)
                console.print(table)
        return

    # Fallback to legacy workspace repo
    ws_dir = _resolve_workspace(workspace)
    repo = WorkspaceRepo(ws_dir)
    data = repo.read_challenges()
    if not data:
        console.print(f"[yellow]ℹ Không có runtime active và không tìm thấy challenges.json trong: {ws_dir}[/yellow]")
        return

    ctf_info = data.get("ctf_info", {})
    challenges = data.get("challenges", [])
    
    total = len(challenges)
    solved = sum(1 for c in challenges if c.get("solved_by_me"))
    total_pts = sum(c.get("points", 0) for c in challenges)
    solved_pts = sum(c.get("points", 0) for c in challenges if c.get("solved_by_me"))

    console.print(Panel(
        f"[bold cyan]{ctf_info.get('title', 'CTF Event')}[/bold cyan] · {ctf_info.get('url', '')}\n"
        f"Tiến độ: [bold green]{solved}/{total}[/bold green] bài ({solved_pts}/{total_pts} điểm)",
        title="[bold yellow]🎯 TIẾN ĐỘ GIẢI ĐẤU[/bold yellow]",
        border_style="cyan"
    ))

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("ID", width=6)
    table.add_column("Category", width=12)
    table.add_column("Challenge Name", width=30)
    table.add_column("Points", justify="right", width=8)
    table.add_column("Trạng thái", justify="center", width=14)

    for c in challenges:
        st = "[bold green]✔ Solved[/bold green]" if c.get("solved_by_me") else "[dim]⏳ Unsolved[/dim]"
        table.add_row(
            str(c.get("id")),
            c.get("category", "Misc"),
            c.get("name", ""),
            str(c.get("points", 0)),
            st
        )
    console.print(table)

@instance_app.command(name="start")
def instance_start(
    challenge_id: str = typer.Argument(..., help="ID của bài tập cần bật container"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w", help="Thư mục workspace")
):
    """Bật dynamic container và tự động patch HOST:PORT vào solve.py."""
    ws_dir = _resolve_workspace(workspace)
    cfg = load_config(ws_dir)
    if not cfg.platform_url:
        console.print("[bold red]❌ Không tìm thấy PLATFORM_URL trong cấu hình .env![/bold red]")
        raise typer.Exit(code=1)

    service = InstanceService(
        workspace_dir=ws_dir,
        platform_url=cfg.platform_url,
        session_cookie=cfg.session_cookie,
        api_token=cfg.api_token
    )
    service.start(challenge_id)

@instance_app.command(name="stop")
def instance_stop(
    challenge_id: str = typer.Argument(..., help="ID của bài tập cần dừng container"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w", help="Thư mục workspace")
):
    """Dừng dynamic container."""
    ws_dir = _resolve_workspace(workspace)
    cfg = load_config(ws_dir)
    if not cfg.platform_url:
        console.print("[bold red]❌ Không tìm thấy PLATFORM_URL trong cấu hình .env![/bold red]")
        raise typer.Exit(code=1)

    service = InstanceService(
        workspace_dir=ws_dir,
        platform_url=cfg.platform_url,
        session_cookie=cfg.session_cookie,
        api_token=cfg.api_token
    )
    service.stop(challenge_id)

@instance_app.command(name="extend")
def instance_extend(
    challenge_id: str = typer.Argument(..., help="ID của bài tập cần gia hạn container"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w", help="Thư mục workspace")
):
    """Gia hạn thời gian chạy container."""
    ws_dir = _resolve_workspace(workspace)
    cfg = load_config(ws_dir)
    if not cfg.platform_url:
        console.print("[bold red]❌ Không tìm thấy PLATFORM_URL trong cấu hình .env![/bold red]")
        raise typer.Exit(code=1)

    service = InstanceService(
        workspace_dir=ws_dir,
        platform_url=cfg.platform_url,
        session_cookie=cfg.session_cookie,
        api_token=cfg.api_token
    )
    service.extend(challenge_id)

@app.command(name="submit")
def submit(
    challenge_id_arg: Optional[str] = typer.Argument(None, help="ID bài tập cần nộp flag"),
    flag_arg: Optional[str] = typer.Argument(None, help="Chuỗi flag cần nộp"),
    challenge_id: Optional[str] = typer.Option(None, "--id", "-i", help="ID bài tập cần nộp flag"),
    flag: Optional[str] = typer.Option(None, "--flag", "-f", help="Chuỗi flag cần nộp"),
    auto: bool = typer.Option(False, "--auto", "-a", help="Quét tự động workspace và nộp flag ngay lập tức"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w", help="Thư mục workspace")
):
    """
    Nộp flag tức thì ('ctf_submit_right_away'). Cảnh báo can thiệp thủ công nếu lỗi!
    Hỗ trợ cả: `ctf submit <id> <flag>` và `ctf submit -i <id> -f <flag>`.
    """
    cid = challenge_id_arg or challenge_id
    flg = flag_arg or flag
    ws_dir = _resolve_workspace(workspace)
    cfg = load_config(ws_dir)
    if not cfg.platform_url:
        console.print("[bold red]❌ Không tìm thấy PLATFORM_URL trong cấu hình .env![/bold red]")
        raise typer.Exit(code=1)

    service = SubmitService(
        workspace_dir=ws_dir,
        platform_url=cfg.platform_url,
        session_cookie=cfg.session_cookie,
        api_token=cfg.api_token,
        flag_format=cfg.flag_format
    )

    if auto:
        service.auto_scan_and_submit()
    else:
        if not cid or not flg:
            console.print("[bold red]❌ Vui lòng cung cấp cả ID và FLAG: `ctf submit <id> <flag>` (hoặc dùng --auto)![/bold red]")
            raise typer.Exit(code=1)
        service.submit(cid, flg)

@chatgpt_app.command(name="prompt")
def chatgpt_prompt_cmd(
    challenge_id: str = typer.Argument(..., help="ID bài tập cần sinh prompt ChatGPT"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w", help="Thư mục workspace"),
    browser: bool = typer.Option(True, "--browser/--no-browser", help="Tự động mở Firefox và copy vào Clipboard")
):
    """
    Trích xuất đề bài + static triage, sinh Prompt cho ChatGPT, copy vào Clipboard và mở Firefox.
    """
    ws_dir = _resolve_workspace(workspace)
    service = ChatGPTService(workspace_dir=ws_dir)
    res = service.prepare_triage_prompt(challenge_id)
    console.print(f"[bold green]✔ Đã tạo Prompt cho {res['challenge_name']} (ID: {challenge_id})[/bold green]")
    console.print(f"  → Tệp: [cyan]{res['prompt_file']}[/cyan]")
    
    if browser:
        service.send_to_firefox_chatgpt(res["prompt_text"])

@chatgpt_app.command(name="deadlock")
def chatgpt_deadlock_cmd(
    challenge_id: str = typer.Argument(..., help="ID bài tập gặp bế tắc"),
    progress: str = typer.Option("Đã phân tích ban đầu và dựng solver thử nghiệm.", "--progress", "-p", help="Những gì đã hiểu và làm được"),
    blocker: str = typer.Option(..., "--blocker", "-b", help="Mô tả điểm nghẽn chính: Z3 timeout, WAF, hàm mã hóa lạ, thiếu gadget..."),
    failed: str = typer.Option(..., "--failed", "-f", help="Các hướng tiếp cận đã thử nhưng thất bại (để ChatGPT không lặp lại)"),
    trace: Optional[str] = typer.Option(None, "--trace", "-t", help="Trích đoạn nhật ký lỗi / execution trace"),
    code: Optional[str] = typer.Option(None, "--code", "-c", help="Đoạn mã solver hoặc decompiled snippet liên quan"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w", help="Thư mục workspace"),
    browser: bool = typer.Option(True, "--browser/--no-browser", help="Tự động mở Firefox và copy vào Clipboard")
):
    """
    Kích hoạt Vòng lặp Tham vấn ChatGPT Web khi gặp bế tắc (Autonomous Deadlock Loop):
    Đóng gói tiến độ + điểm nghẽn + các hướng thất bại, sinh prompt chuyên sâu và đẩy lên ChatGPT Web trên Firefox.
    """
    ws_dir = _resolve_workspace(workspace)
    service = ChatGPTService(workspace_dir=ws_dir)
    res = service.prepare_deadlock_prompt(
        challenge_id=challenge_id,
        progress=progress,
        blocker=blocker,
        failed_attempts=failed,
        error_trace=trace,
        code_snippet=code
    )
    console.print(f"[bold red]⚠️ ĐÃ KÍCH HOẠT DEADLOCK ESCALATION LOOP CHO {res['challenge_name']} (ID: {challenge_id})[/bold red]")
    console.print(f"  → Tệp Deadlock Prompt: [cyan]{res['prompt_file']}[/cyan]")
    
    if browser:
        service.send_to_firefox_chatgpt(res["prompt_text"])

@chatgpt_app.command(name="save")
def chatgpt_save_cmd(
    challenge_id: str = typer.Argument(..., help="ID bài tập"),
    file: Optional[Path] = typer.Option(None, "--file", "-f", help="Tệp chứa phản hồi từ ChatGPT"),
    text: Optional[str] = typer.Option(None, "--text", "-t", help="Nội dung phản hồi trực tiếp"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w", help="Thư mục workspace")
):
    """
    Lưu nội dung phân tích/hướng dẫn từ ChatGPT vào workspace và reverse-skill/work/.
    """
    ws_dir = _resolve_workspace(workspace)
    service = ChatGPTService(workspace_dir=ws_dir)

    content = ""
    if file and file.is_file():
        content = file.read_text(encoding="utf-8")
    elif text:
        content = text
    else:
        console.print("[bold red]❌ Vui lòng cung cấp --file <path> hoặc --text '<nội dung>'![/bold red]")
        raise typer.Exit(code=1)

    service.save_chatgpt_guidance(challenge_id, content)

@chatgpt_app.command(name="resolve")
def chatgpt_resolve_cmd(
    challenge_id: str = typer.Argument(..., help="ID bài tập"),
    status: str = typer.Option("pending", "--status", "-s", help="'solved' nếu ChatGPT giải xong, 'pending' nếu chưa xong cần mang về giải"),
    reason: Optional[str] = typer.Option(None, "--reason", "-r", help="Lý do chưa giải được: 'too_hard' (quá khó/thử bế tắc), 'no_runtime' (không thực thi được, cần gdb/IDA/container), hoặc ghi chú tự do"),
    tried: Optional[str] = typer.Option(None, "--tried", "-t", help="Tóm tắt các hướng/cách ChatGPT đã thử nhưng chưa ra flag"),
    flag: Optional[str] = typer.Option(None, "--flag", "-f", help="Flag do ChatGPT tìm ra (nếu có)"),
    submit: bool = typer.Option(False, "--submit", help="Tự động nộp flag lên platform ngay nếu status là solved"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w", help="Thư mục workspace")
):
    """
    Đánh dấu kết quả từ ChatGPT:
    - 'solved': ChatGPT đã giải xong -> để sang 1 bên, hoàn thành!
    - 'pending': ChatGPT chưa giải được -> phân loại lý do (quá khó vs thiếu runtime) và đưa vào hàng đợi Anti-IDE.
    """
    ws_dir = _resolve_workspace(workspace)
    service = ChatGPTService(workspace_dir=ws_dir)
    ok = service.resolve_challenge_chatgpt(
        challenge_id,
        status=status,
        reason=reason,
        flag=flag,
        tried=tried
    )
    if ok:
        if status == "solved":
            console.print(f"[bold green]✔ Bài ID {challenge_id} đã được ChatGPT giải xong! Đã đưa sang danh sách hoàn thành.[/bold green]")
            if flag and submit:
                cfg = load_config(ws_dir)
                if cfg.platform_url:
                    sub_service = SubmitService(
                        workspace_dir=ws_dir,
                        platform_url=cfg.platform_url,
                        session_cookie=cfg.session_cookie,
                        api_token=cfg.api_token,
                        flag_format=cfg.flag_format
                    )
                    sub_service.submit(challenge_id, flag)
        else:
            r_msg = f" ({reason})" if reason else ""
            console.print(f"[bold yellow]⏳ Bài ID {challenge_id} chưa được ChatGPT giải{r_msg} -> Đã lưu các hướng đã thử và đưa về hàng đợi Anti-IDE + reverse-skill giải tiếp![/bold yellow]")
    else:
        console.print(f"[bold red]❌ Không tìm thấy Challenge ID {challenge_id}![/bold red]")

@chatgpt_app.command(name="report")
def chatgpt_report_cmd(
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w", help="Thư mục workspace")
):
    """
    Báo cáo tình trạng triage:
    - Bài nào ChatGPT đã giải xong (Đã để sang một bên)
    - Bài nào ChatGPT chưa giải được: phân loại bài quá khó vs bài không thực thi được
    """
    ws_dir = _resolve_workspace(workspace)
    service = ChatGPTService(workspace_dir=ws_dir)
    rep = service.get_triage_report()

    solved_list = rep["chatgpt_solved"]
    pending_list = rep["needs_local"]
    untriaged_list = rep["untriaged"]

    console.print(Panel(
        f"🟢 [bold green]Đã giải xong (Bởi ChatGPT / Solved):[/bold green] {len(solved_list)} bài (Đã xếp sang một bên)\n"
        f"🟠 [bold yellow]Chưa xong (Cần Local AI giải tiếp):[/bold yellow] {len(pending_list)} bài\n"
        f"⚪ [dim]Chưa đưa lên ChatGPT:[/dim] {len(untriaged_list)} bài",
        title="[bold cyan]📊 BÁO CÁO PHÂN LOẠI TRIAGE CHATGPT[/bold cyan]"
    ))

    if solved_list:
        t_solved = Table(title="🟢 CÁC BÀI ĐÃ HOÀN THÀNH (ĐỂ SANG MỘT BÊN)", header_style="bold green")
        t_solved.add_column("ID", width=6)
        t_solved.add_column("Category", width=12)
        t_solved.add_column("Tên bài", width=25)
        t_solved.add_column("Points", justify="right", width=8)
        t_solved.add_column("Flag", style="yellow", width=30)
        for s in solved_list:
            t_solved.add_row(str(s["id"]), s.get("category", ""), s.get("name", ""), str(s.get("points", 0)), s.get("flag") or "✔ Solved")
        console.print(t_solved)

    if pending_list:
        t_pend = Table(title="🟠 CÁC BÀI CẦN MANG VỀ ĐÂY ĐỂ GIẢI TIẾP (LOCAL QUEUE)", header_style="bold yellow")
        t_pend.add_column("ID", width=6)
        t_pend.add_column("Category", width=10)
        t_pend.add_column("Tên bài", width=22)
        t_pend.add_column("Points", justify="right", width=6)
        t_pend.add_column("Lý do chưa giải được", style="bold red", width=30)
        t_pend.add_column("Hướng đã thử", style="dim", width=25)
        for p in pending_list:
            t_pend.add_row(
                str(p["id"]),
                p.get("category", ""),
                p.get("name", ""),
                str(p.get("points", 0)),
                p.get("reason", "Chờ giải"),
                p.get("tried") or "-"
            )
        console.print(t_pend)

@app.command(name="pending")
def show_pending_cmd(
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w", help="Thư mục workspace")
):
    """
    Liệt kê tất cả các bài tập chưa được giải quyết để Anti-IDE tiếp tục xử lý.
    """
    ws_dir = _resolve_workspace(workspace)
    service = ChatGPTService(workspace_dir=ws_dir)
    rep = service.get_triage_report()
    pending_list = rep["needs_local"] + rep["untriaged"]

    if not pending_list:
        console.print("[bold green]🎉 Tuyệt vời! Không còn bài nào đang chờ giải.[/bold green]")
        return

    table = Table(title=f"🎯 Danh sách {len(pending_list)} bài cần Anti-IDE tiếp tục giải", header_style="bold cyan")
    table.add_column("ID", width=6)
    table.add_column("Category", width=10)
    table.add_column("Tên bài", width=25)
    table.add_column("Points", justify="right", width=6)
    table.add_column("Phân loại / Lý do", style="yellow")
    for p in pending_list:
        table.add_row(
            str(p["id"]),
            p.get("category", ""),
            p.get("name", ""),
            str(p.get("points", 0)),
            p.get("reason", "Chưa triage")
        )
    console.print(table)



@env_app.command(name="set")
def env_set(
    url: Optional[str] = typer.Option(None, "--url", "-u", help="PLATFORM_URL"),
    cookie: Optional[str] = typer.Option(None, "--cookie", "-c", help="SESSION_COOKIE"),
    token: Optional[str] = typer.Option(None, "--token", "-t", help="API_TOKEN"),
    flag_format: Optional[str] = typer.Option(None, "--format", "-f", help="FLAG_FORMAT"),
    target_env: Optional[Path] = typer.Option(None, "--file", help="Đường dẫn tệp .env cần ghi")
):
    """Thiết lập nhanh các biến trong tệp .env cho Anti-IDE."""
    env_file = target_env or (Path.cwd() / ".env")
    vals = {}
    if url is not None:
        vals["PLATFORM_URL"] = url
    if cookie is not None:
        vals["SESSION_COOKIE"] = cookie
    if token is not None:
        vals["API_TOKEN"] = token
    if flag_format is not None:
        vals["FLAG_FORMAT"] = flag_format
        
    saved = save_env_file(env_file, vals)
    console.print(f"[bold green]✔ Đã cập nhật tệp cấu hình:[/bold green] {saved}")

@env_app.command(name="show")
def env_show(
    target_env: Optional[Path] = typer.Option(None, "--file", help="Đường dẫn tệp .env")
):
    """Hiển thị cấu hình xác thực hiện tại."""
    cfg = load_config(explicit_env=target_env)
    env_path = target_env or find_env_file()
    console.print(f"[cyan]Tệp .env nạp từ:[/cyan] {env_path or 'Không tìm thấy (dùng biến môi trường hệ thống)'}")
    
    table = Table(title="Cấu hình Anti-IDE CTF Lifecycle", show_header=True)
    table.add_column("Tên biến", style="bold")
    table.add_column("Giá trị", style="yellow")
    
    table.add_row("PLATFORM_URL", cfg.platform_url or "[dim]None[/dim]")
    c_disp = f"{cfg.session_cookie[:15]}..." if cfg.session_cookie else "[dim]None[/dim]"
    table.add_row("SESSION_COOKIE", c_disp)
    t_disp = f"{cfg.api_token[:10]}..." if cfg.api_token else "[dim]None[/dim]"
    table.add_row("API_TOKEN", t_disp)
    table.add_row("FLAG_FORMAT", cfg.flag_format or "[dim]None[/dim]")
    table.add_row("TIMEOUT", str(cfg.timeout))
    console.print(table)


# ==============================================================================
# STRATEGIC ADVISOR MULTI-AGENT SUBSYSTEM (Oracle + PAL + Anti-IDE/OpenCode)
# ==============================================================================

@advisor_app.command(name="init")
def advisor_init_cmd(
    challenge_id: str = typer.Argument(..., help="ID hoặc tên bài tập cần khởi tạo state cố vấn"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w", help="Thư mục CTF Workspace"),
    force: bool = typer.Option(False, "--force", "-f", help="Ghi đè lại state và findings ban đầu")
):
    """
    Khởi tạo hệ thống trạng thái .advisor/ cho bài tập:
    Tạo state.json, findings.md (kèm static triage), hypotheses.md, experiments.jsonl.
    """
    ws_dir = _resolve_workspace(workspace)
    service = AdvisorService(workspace_dir=ws_dir)
    res = service.init_challenge_advisor(challenge_id, force=force)
    console.print(f"[bold green]✔ Đã khởi tạo thành công hệ thống .advisor/ cho Challenge ID: {challenge_id}[/bold green]")
    console.print(f"📁 Thư mục lưu trữ: [cyan]{res['advisor_dir']}[/cyan]")


@advisor_app.command(name="consult")
def advisor_consult_cmd(
    challenge_id: str = typer.Argument(..., help="ID hoặc tên bài tập cần tham vấn Strategic Advisor"),
    instruction: Optional[str] = typer.Option(None, "--instruction", "-i", help="Chỉ thị bổ sung của Executor"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w", help="Thư mục CTF Workspace")
):
    """
    Gom ngữ cảnh 4 tầng (L0-L3), kết nối trực tiếp đến ChatGPT Web qua Oracle Browser Bridge,
    nhận bảng chỉ dẫn 6 phần (ASSESSMENT, HYPOTHESES, NEXT_ACTIONS...) và lưu vào guidance.md.
    """
    ws_dir = _resolve_workspace(workspace)
    service = AdvisorService(workspace_dir=ws_dir)
    res = service.consult(challenge_id, extra_instruction=instruction)
    console.print(f"[bold green]✔ Vòng tham vấn #{res['iteration']} hoàn tất![/bold green]")
    if res.get("active_hypothesis"):
        console.print(f"💡 Giả thuyết hành động: [bold yellow]{res['active_hypothesis']}[/bold yellow]")
    console.print(f"📄 Xem chi tiết chỉ đạo tại: [cyan]{res['guidance_file']}[/cyan]")


@advisor_app.command(name="report")
def advisor_report_cmd(
    challenge_id: str = typer.Argument(..., help="ID hoặc tên bài tập"),
    exp_id: str = typer.Option(..., "--exp", "-e", help="Mã thực nghiệm (ví dụ: EXP-001, EXP-002)"),
    actions: str = typer.Option(..., "--actions", "-a", help="Các lệnh hoặc thao tác đã thực hiện"),
    observed: str = typer.Option(..., "--observed", "-o", help="Hiện tượng ghi nhận thực tế"),
    status: str = typer.Option("REJECTED", "--status", "-s", help="Kết quả giả thuyết: CONFIRMED, REJECTED, hoặc INCONCLUSIVE"),
    diff: Optional[str] = typer.Option(None, "--diff", "-d", help="Khác biệt giữa kỳ vọng và thực tế"),
    evidence: Optional[str] = typer.Option(None, "--evidence", help="Dữ liệu chắt lọc (registers, leak snippet, HTTP code)"),
    questions: Optional[str] = typer.Option(None, "--questions", "-q", help="Câu hỏi mới cần Advisor giải đáp"),
    no_consult: bool = typer.Option(False, "--no-consult", help="Chỉ ghi log báo cáo, không tự động kích hoạt Oracle followup"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w", help="Thư mục CTF Workspace")
):
    """
    Báo cáo kết quả thực thi của Executor cho Strategic Advisor.
    Tự động quản lý Hypothesis Budget (cảnh báo nếu fail quá 2 lần) và gửi --followup vào Oracle.
    """
    ws_dir = _resolve_workspace(workspace)
    service = AdvisorService(workspace_dir=ws_dir)
    res = service.report_execution(
        challenge_id=challenge_id,
        experiment_id=exp_id,
        actions=actions,
        observed=observed,
        status=status,
        diff=diff,
        evidence=evidence,
        open_questions=questions,
        auto_consult=not no_consult
    )
    console.print(f"[bold green]✔ Đã ghi nhận báo cáo thực nghiệm {exp_id} ({res['status']})![/bold green]")
    console.print(f"📄 Báo cáo lưu tại: [cyan]{res['report_file']}[/cyan]")
    if res.get("is_stalled"):
        console.print("[bold red]⚠️ Trạng thái hiện tại: STALLED (Bế tắc). Hãy kích hoạt `./ctf advisor escalate` để hội chẩn PAL MCP![/bold red]")


@advisor_app.command(name="escalate")
def advisor_escalate_cmd(
    challenge_id: str = typer.Argument(..., help="ID hoặc tên bài tập cần thẩm định chéo"),
    reason: str = typer.Option(..., "--reason", "-r", help="Lý do bế tắc hoặc nghi ngờ giả định của ChatGPT sai"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w", help="Thư mục CTF Workspace")
):
    """
    Kích hoạt cơ chế Thẩm định chéo PAL MCP khi ChatGPT Web bị sa lầy (tunnel vision):
    Chất vấn lại toàn bộ giả định nền tảng và đề xuất alternative vectors.
    """
    ws_dir = _resolve_workspace(workspace)
    service = AdvisorService(workspace_dir=ws_dir)
    res = service.escalate_pal(challenge_id, reason=reason)
    console.print(f"[bold green]✔ Đã gửi hồ sơ thẩm định chéo vào phiên làm việc của Strategic Advisor![/bold green]")


@advisor_app.command(name="status")
def advisor_status_cmd(
    challenge_id: str = typer.Argument(..., help="ID hoặc tên bài tập cần xem trạng thái"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w", help="Thư mục CTF Workspace")
):
    """
    Hiển thị bảng theo dõi ReAct Dashboard của bài tập:
    Phase, Iteration, Active Hypothesis, Hypothesis Budget, Oracle Session ID, Escalation status.
    """
    ws_dir = _resolve_workspace(workspace)
    service = AdvisorService(workspace_dir=ws_dir)
    service.get_status(challenge_id)


# ==============================================================================
# DREAM-RSI META-LAYER SUBSYSTEM (Discovery Trees, Replay, Policies, Knowledge)
# ==============================================================================

@meta_app.command(name="tree")
def meta_tree_cmd(
    challenge_id: str = typer.Argument(..., help="ID hoặc tên bài tập cần xem cây khám phá"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w", help="Thư mục CTF Workspace")
):
    """
    Hiển thị trực quan Cây Khám Phá (Discovery Tree / DAG) của bài tập trên Terminal:
    Nút giả thuyết, hành động, quan sát, các nhánh bế tắc bị cắt tỉa (pruned), và đường dẫn cờ.
    """
    ws_dir = _resolve_workspace(workspace)
    service = AdvisorService(workspace_dir=ws_dir)
    tree = service.get_discovery_tree(challenge_id)
    
    console.print(tree.render_rich_tree())
    
    # Hiển thị tóm tắt thông số cây
    winning_path = tree.get_winning_path()
    active_leaves = tree.get_active_leaves()
    pruned_nodes = [n for n in tree.nodes.values() if n.status == "pruned"]
    
    table = Table(title=f"📊 Thống Kê Không Gian Khám Phá ({tree.challenge_name or challenge_id})", show_header=True)
    table.add_column("Chỉ Số Cây DAG", style="cyan")
    table.add_column("Giá Trị", style="yellow")
    
    table.add_row("Tổng Số Nút", str(len(tree.nodes)))
    table.add_row("Nhánh Đang Sống (Active Leaves)", str(len(active_leaves)))
    table.add_row("Nhánh Chết Bị Cắt Tỉa (Pruned)", str(len(pruned_nodes)))
    table.add_row("Đường Đi Chiến Thắng (Winning Path)", f"[bold green]{len(winning_path)} bước[/bold green]" if winning_path else "[dim]Chưa giải xong[/dim]")
    
    console.print(table)


@meta_app.command(name="replay")
def meta_replay_cmd(
    challenge_id: str = typer.Argument(..., help="ID hoặc tên bài tập cần chạy mô phỏng Replay"),
    policy: Optional[Path] = typer.Option(None, "--policy", "-p", help="Đường dẫn file chính sách (.yaml) để mô phỏng"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w", help="Thư mục CTF Workspace")
):
    """
    Chạy mô phỏng Replay Simulator (chuẩn Dream-RSI) một chính sách tác chiến
    trên cây khám phá thực tế mà KHÔNG cần chạy lại binary hay gọi lại LLM.
    """
    ws_dir = _resolve_workspace(workspace)
    service = AdvisorService(workspace_dir=ws_dir)
    res = service.replay_simulation(challenge_id, policy_file=policy)
    
    table = Table(title=f"🎮 Replay Simulation Result: {challenge_id} (Policy: {res.policy_name} v{res.policy_version})")
    table.add_column("Chỉ Số Replay", style="cyan bold")
    table.add_column("Kết Quả Mô Phỏng", style="white")
    
    st_color = "green" if res.success else "yellow" if res.status == "STOPPED_BUDGET_EXCEEDED" else "red"
    table.add_row("Trạng Thái Replay", f"[{st_color} bold]{res.status}[/{st_color} bold]")
    table.add_row("Tìm Thấy Cờ (Flag Found)", "✔ Có" if res.flag_found else "✖ Không")
    table.add_row("Tổng Số Bước Duyệt (Steps)", str(res.steps_taken))
    table.add_row("Số Lần Gọi Cố Vấn (Advisor)", str(res.advisor_calls))
    table.add_row("Số Hành Động Thực Thi (Executor)", str(res.executor_actions))
    table.add_row("Số Nhánh Chết Cắt Tỉa (Pruned)", str(res.dead_branches_pruned))
    table.add_row("Điểm Số Hiệu Năng (Score)", f"[bold green]{res.score:.0f}[/bold green]" if res.score > 0 else f"[red]{res.score:.0f}[/red]")
    table.add_row("Ghi Chú Đánh Giá", res.notes)
    
    console.print(table)


@meta_app.command(name="benchmark")
def meta_benchmark_cmd(
    policy_a: Optional[Path] = typer.Option(None, "--policy-a", help="Đường dẫn Policy A (Incumbent - Mặc định: default_v1.yaml)"),
    policy_b: Optional[Path] = typer.Option(None, "--policy-b", help="Đường dẫn Policy B (Candidate - Mặc định: fast_triage_v1.yaml)"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w", help="Thư mục CTF Workspace")
):
    """
    Chấm điểm và so sánh trực tiếp hiệu năng giữa 2 chính sách tác chiến (A vs B)
    trên toàn bộ tập dữ liệu cây khám phá lịch sử trong workspace.
    """
    from ..meta.policy import ExplorationPolicy
    from ..meta.scorer import PolicyScorer
    from ..meta.tree import DiscoveryTree

    ws_dir = _resolve_workspace(workspace)
    policies_dir = Path(__file__).resolve().parents[2] / "policies"
    
    p_a_path = policy_a or (policies_dir / "default_v1.yaml")
    p_b_path = policy_b or (policies_dir / "fast_triage_v1.yaml")
    
    if not p_a_path.is_file() or not p_b_path.is_file():
        console.print("[red]❌ Không tìm thấy tệp policy so sánh.[/red]")
        return
        
    p_a = ExplorationPolicy.load_from_file(p_a_path)
    p_b = ExplorationPolicy.load_from_file(p_b_path)
    
    # Thu thập tất cả Discovery Trees trong workspace
    trees = []
    repo = WorkspaceRepo(ws_dir)
    for cdir in repo.iter_challenge_dirs():
        tree_file = cdir / ".advisor" / "tree.json"
        if tree_file.is_file():
            try:
                trees.append(DiscoveryTree.load(tree_file))
            except Exception:
                pass
                
    if not trees:
        console.print("[yellow]⚠️ Chưa tìm thấy cây khám phá (.advisor/tree.json) nào trong workspace để benchmark.[/yellow]")
        console.print("[dim]Hãy chạy `./ctf advisor init <ID>` hoặc giải thử một bài để tạo dữ liệu lịch sử![/dim]")
        return
        
    console.print(f"[cyan]🚀 Đang thực hiện benchmark trên {len(trees)} bài tập trong lịch sử...[/cyan]")
    cmp_table = PolicyScorer.compare_policies(p_a, p_b, trees)
    console.print(cmp_table)


@meta_app.command(name="compile")
def meta_compile_cmd(
    challenge_id: str = typer.Argument(..., help="ID bài tập cần trích xuất Thẻ Tri Thức"),
    flag: Optional[str] = typer.Option(None, "--flag", "-f", help="Chuỗi cờ của bài thi"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w", help="Thư mục CTF Workspace")
):
    """
    Biên dịch thủ công kinh nghiệm tác chiến từ Cây Khám Phá của một bài thi đã giải
    thành Thẻ Tri Thức (Declarative Technique Card) lưu vào knowledge_base/.
    """
    ws_dir = _resolve_workspace(workspace)
    service = AdvisorService(workspace_dir=ws_dir)
    card_path = service.compile_knowledge(challenge_id, flag=flag)
    console.print(f"[bold green]✔ Đã biên dịch thành công Thẻ Tri Thức tại:[/bold green] [cyan]{card_path}[/cyan]")


@meta_app.command(name="cards")
def meta_cards_cmd(
    category: Optional[str] = typer.Option(None, "--category", "-c", help="Lọc theo Category (pwn, rev, crypto, web, misc)")
):
    """
    Liệt kê toàn bộ Thẻ Tri Thức (Declarative Technique Cards) đã tích lũy trong knowledge_base.
    """
    import json
    kb_dir = Path(__file__).resolve().parents[2] / "knowledge_base"
    index_file = kb_dir / "index.json"
    
    if not index_file.is_file():
        console.print("[yellow]Chưa có Thẻ Tri Thức nào được biên dịch trong knowledge_base/index.json.[/yellow]")
        return
        
    try:
        index = json.loads(index_file.read_text(encoding="utf-8"))
    except Exception:
        index = {}
        
    table = Table(title="📚 Declarative Knowledge Base (Technique Cards)")
    table.add_column("Challenge ID", style="cyan bold")
    table.add_column("Tên Bài", style="white")
    table.add_column("Category", style="yellow")
    table.add_column("Đã Có Cờ?", style="green")
    table.add_column("Đường Dẫn Thẻ Tri Thức", style="dim")
    
    cat_filter = category.lower().strip() if category else None
    count = 0
    for cid, data in index.items():
        if cat_filter and data.get("category", "").lower() != cat_filter:
            continue
        count += 1
        table.add_row(
            str(cid),
            data.get("name", ""),
            data.get("category", "").upper(),
            "✔ Có" if data.get("has_flag") else "✖ Chưa",
            data.get("card_path", "")
        )
        
    if count == 0:
        console.print(f"[yellow]Không tìm thấy Thẻ Tri Thức nào cho Category: {category}[/yellow]")
    else:
        console.print(table)


# ==========================================
# 📝 PROMPT MASTER ENGINE COMMANDS
# ==========================================

@prompt_app.command(name="capsule")
def prompt_capsule_cmd(
    challenge_id: str = typer.Argument(..., help="ID bài tập cần trích xuất State Capsule"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w", help="Thư mục CTF Workspace"),
):
    """
    Trích xuất và hiển thị Viên Nang Trạng Thái (State Capsule) chắt lọc:
    Confirmed Facts, Active Hypothesis, Rejected Hypotheses, Recent Progress, và Retrieved Experience.
    """
    ws_dir = _resolve_workspace(workspace)
    service = AdvisorService(workspace_dir=ws_dir)
    capsule = service.get_state_capsule(challenge_id)
    console.print(
        Panel(
            capsule.to_markdown(),
            title=f"💊 State Capsule: {capsule.challenge_name} (ID: {capsule.challenge_id})",
            border_style="cyan",
        )
    )


@prompt_app.command(name="lint")
def prompt_lint_cmd(
    challenge_id: str = typer.Argument(..., help="ID bài tập cần kiểm tra Prompt"),
    agent: str = typer.Option("advisor", "--agent", "-a", help="Mục tiêu agent (advisor hoặc executor)"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w", help="Thư mục CTF Workspace"),
):
    """
    Chạy Prompt Linter phát hiện 37 anti-patterns làm giảm hiệu suất reasoning
    (thiếu Stop Conditions, thiếu Scope Boundary, trôi ngữ cảnh, v.v.) và tự động sửa lỗi.
    """
    ws_dir = _resolve_workspace(workspace)
    service = AdvisorService(workspace_dir=ws_dir)
    target_agent = agent.lower().strip()
    if target_agent not in ["advisor", "executor"]:
        console.print("[red]❌ Target agent phải là 'advisor' hoặc 'executor'.[/red]")
        return

    repaired_spec, violations = service.lint_challenge_prompt(challenge_id, target_agent=target_agent)

    table = Table(title=f"🔍 Prompt Linter Report: {target_agent.upper()} Contract")
    table.add_column("Anti-Pattern Rule", style="yellow bold")
    table.add_column("Mức Độ (Severity)", style="red")
    table.add_column("Mô Tả Vi Phạm", style="white")
    table.add_column("Hành Động Tự Sửa (Auto-Repair)", style="green")

    if not violations:
        console.print(
            Panel(
                f"[bold green]✔ Prompt đạt chuẩn Prompt Master! Không phát hiện anti-pattern nào cho {target_agent}.[/bold green]",
                border_style="green",
            )
        )
    else:
        for v in violations:
            sev_color = "red bold" if v.severity == "CRITICAL" else "yellow"
            table.add_row(
                v.rule_id,
                f"[{sev_color}]{v.severity}[/{sev_color}]",
                v.description,
                v.auto_fixed or "None",
            )
        console.print(table)
        auto_fixed_count = len([v for v in violations if v.auto_fixed])
        console.print(
            f"[bold green]✔ Đã tự động vá và chuẩn hóa {auto_fixed_count} vi phạm vào PromptSpec![/bold green]"
        )


@prompt_app.command(name="show")
def prompt_show_cmd(
    challenge_id: str = typer.Argument(..., help="ID bài tập cần hiển thị Prompt"),
    agent: str = typer.Option("advisor", "--agent", "-a", help="Mục tiêu agent (advisor hoặc executor)"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w", help="Thư mục CTF Workspace"),
):
    """
    Biên dịch và hiển thị toàn bộ Prompt hợp đồng (Template H: ReAct cho Executor, Template E: Auditable Reasoning cho Advisor).
    """
    ws_dir = _resolve_workspace(workspace)
    service = AdvisorService(workspace_dir=ws_dir)
    target_agent = agent.lower().strip()
    if target_agent not in ["advisor", "executor"]:
        console.print("[red]❌ Target agent phải là 'advisor' hoặc 'executor'.[/red]")
        return

    prompt_text, violations = service.show_compiled_prompt(challenge_id, target_agent=target_agent)
    template_name = (
        "Template E (Auditable Reasoning)" if target_agent == "advisor" else "Template H (ReAct + Stop Conditions)"
    )
    console.print(
        Panel(prompt_text, title=f"📜 Compiled Prompt Contract: {template_name}", border_style="green")
    )
    if violations:
        console.print(f"[dim]ℹ Lưu ý: Prompt đã được lọc qua {len(violations)} quy tắc linter.[/dim]")


# ==============================================================================
# CLEANUP CLI COMMANDS
# ==============================================================================

@cleanup_app.command(name="challenge")
def cleanup_challenge_cmd(
    challenge_id: str = typer.Argument(..., help="ID của challenge cần xóa runtime"),
    event: Optional[str] = typer.Option(None, "--event", "-e", help="Event ID (mặc định lấy event active)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Chỉ kiểm tra và in ra danh sách, không xóa thật")
):
    """Xóa dữ liệu runtime tạm của một challenge cụ thể."""
    rt = RuntimeManager()
    events = rt.list_events()
    eid = event or (events[0] if events else "default_event")
    cpath = rt.challenge_path(eid, challenge_id)
    if not cpath.exists():
        console.print(f"[yellow]⚠️ Không tìm thấy runtime cho Challenge ID '{challenge_id}' trong event '{eid}'[/yellow]")
        return
    if dry_run:
        console.print(f"[cyan][DRY-RUN] Sẽ xóa thư mục: {cpath}[/cyan]")
        return
    rt.cleanup_challenge(eid, challenge_id)
    console.print(f"[bold green]✔ Đã xóa an toàn runtime của challenge: {challenge_id}[/bold green]")

@cleanup_app.command(name="event")
def cleanup_event_cmd(
    event_id: Optional[str] = typer.Argument(None, help="Event ID cần xóa (mặc định xóa event active)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Chỉ kiểm tra và in ra danh sách, không xóa thật")
):
    """Xóa toàn bộ dữ liệu runtime của một giải CTF (giữ nguyên Knowledge)."""
    rt = RuntimeManager()
    events = [event_id] if event_id else rt.list_events()
    if not events:
        console.print("[yellow]ℹ Không có event runtime nào để dọn dẹp.[/yellow]")
        return
    for eid in events:
        epath = rt.event_path(eid)
        if dry_run:
            console.print(f"[cyan][DRY-RUN] Sẽ xóa event runtime: {epath}[/cyan]")
        else:
            rt.cleanup_event(eid)
            console.print(f"[bold green]✔ Đã xóa sạch runtime của event: {eid}[/bold green]")

@cleanup_app.command(name="all")
def cleanup_all_cmd(
    dry_run: bool = typer.Option(False, "--dry-run", help="Chỉ kiểm tra và in ra danh sách, không xóa thật")
):
    """Xóa sạch TOÀN BỘ thư mục .runtime/ (giữ nguyên Knowledge)."""
    rt = RuntimeManager()
    cleaned = rt.cleanup_all(dry_run=dry_run)
    if dry_run:
        console.print(f"[cyan][DRY-RUN] Sẽ xóa {len(cleaned)} event runtime(s): {[str(p) for p in cleaned]}[/cyan]")
    else:
        console.print(f"[bold green]✔ Đã xóa sạch toàn bộ runtime CTF ({len(cleaned)} events). Không có tri thức nào bị ảnh hưởng![/bold green]")


# ==============================================================================
# KNOWLEDGE CLI COMMANDS
# ==============================================================================

@knowledge_app.command(name="list")
def knowledge_list_cmd(
    category: Optional[str] = typer.Option(None, "--category", "-C", help="Lọc theo category")
):
    """Xem danh sách các Thẻ Tri Thức (Knowledge Cards) đã tích lũy."""
    import json
    compiler = KnowledgeCompiler()
    index_file = compiler.index_file
    if not index_file.exists():
        console.print("[yellow]ℹ Chưa có Thẻ Tri Thức nào được tạo.[/yellow]")
        return
    index = json.loads(index_file.read_text(encoding="utf-8"))
    table = Table(title="📚 Declarative Knowledge Cards", show_header=True, header_style="bold magenta")
    table.add_column("ID", style="dim", width=16)
    table.add_column("Category", style="cyan", width=12)
    table.add_column("Name", style="bold", width=30)
    table.add_column("Card Path", width=35)
    table.add_column("Updated At", style="dim", width=22)

    for cid, item in index.items():
        cat = item.get("category", "")
        if category and cat.lower() != category.lower().strip():
            continue
        table.add_row(str(item.get("id", cid)), cat, item.get("name", ""), item.get("card_path", ""), item.get("updated_at", ""))
    console.print(table)

@knowledge_app.command(name="search")
def knowledge_search_cmd(
    query: str = typer.Argument(..., help="Từ khóa tìm kiếm tri thức"),
    category: Optional[str] = typer.Option(None, "--category", "-C", help="Giới hạn theo category")
):
    """Tìm kiếm Thẻ Tri Thức liên quan."""
    retriever = KnowledgeRetriever()
    cards = retriever.retrieve_relevant_cards(category=category or "misc", keywords=[query], max_cards=5)
    if not cards:
        console.print(f"[yellow]ℹ Không tìm thấy thẻ tri thức khớp với từ khóa: {query}[/yellow]")
        return
    for c in cards:
        console.print(Panel(c["content"][:600] + "...", title=f"[bold green]{c['name']} ({c['category']})[/bold green]"))

@knowledge_app.command(name="migrate-notes")
def knowledge_migrate_notes_cmd(
    file_path: Optional[Path] = typer.Option(None, "--file", "-f", help="Đường dẫn tệp SAVED_NOTES.md")
):
    """Chuyển đổi các bài viết cũ từ SAVED_NOTES.md thành các Thẻ Tri Thức chuẩn YAML."""
    target_file = file_path
    if not target_file:
        curr = Path.cwd().resolve()
        for p in [curr, *curr.parents]:
            cand = p / "SAVED_NOTES.md"
            if cand.is_file():
                target_file = cand
                break
    if not target_file or not target_file.is_file():
        console.print("[bold red]❌ Không tìm thấy tệp SAVED_NOTES.md![/bold red]")
        raise typer.Exit(code=1)

    console.print(f"[cyan]🔄 Đang tiến hành migrate từ: {target_file}...[/cyan]")
    compiler = KnowledgeCompiler()
    count = compiler.migrate_saved_notes(target_file)
    console.print(f"[bold green]✔ Đã chuyển đổi thành công {count} bài tập thành các Thẻ Tri Thức trong knowledge_base/cards/![/bold green]")
    console.print("[dim]Tệp SAVED_NOTES.md cũ được giữ lại an toàn làm tài liệu lưu trữ legacy.[/dim]")

