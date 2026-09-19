import os
import shutil
from pathlib import Path
from typing import Optional, List
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from ..config import load_config, save_env_file, find_env_file
from ..models import Challenge
from ..platforms.registry import create_platform, detect_platform_type
from ..runtime.manager import RuntimeManager
from ..knowledge.github_provider import GitHubKnowledgeProvider
from ..knowledge.local_provider import LocalKnowledgeProvider
from ..knowledge.models import KnowledgeQuery
from ..knowledge.cache import KnowledgeCache
from ..knowledge.outbox import KnowledgeOutbox
from ..tools.registry import ToolManager
from ..services.pull_service import PullService
from ..services.instance_service import InstanceService
from ..services.submit_service import SubmitService
from ..services.advisor_service import AdvisorService
from ..services.orchestrator import ChallengeOrchestrator
from ..advisor.browser_bridge import BrowserBridge
from ..triage.static import StaticTriage
from ..triage.fingerprint import FingerprintEngine
from ..meta.tree import DiscoveryTree
from ..meta.policy import ExplorationPolicy
from ..meta.scorer import PolicyScorer
from ..meta.knowledge_compiler import KnowledgeCompiler

app = typer.Typer(
    name="ctf",
    help="⚡ CTF Anti-IDE Suite — Autonomous CTF Lifecycle & Solving Tool for Anti-IDE",
    add_completion=False,
    no_args_is_help=True
)
instance_app = typer.Typer(help="🐳 Quản lý dynamic container (start, stop, extend)")
env_app = typer.Typer(help="⚙ Quản lý cấu hình xác thực tệp .env")
advisor_app = typer.Typer(help="🧠 Strategic Advisor Bridge (Anti-IDE/OpenCode ↔ ChatGPT Web via Oracle)")
meta_app = typer.Typer(help="🧬 Dream-RSI Meta-Layer: Discovery Trees, Policies, Offline Replay & Declarative Memory")
prompt_app = typer.Typer(help="📝 Prompt Master Engine: Contract Compiling, Linting & State Capsules")
cleanup_app = typer.Typer(help="🧹 Quản lý dọn dẹp runtime tạm thời (challenge, event, all)")
knowledge_app = typer.Typer(help="📚 Quản lý Thẻ Tri Thức Ngoại Vi (Remote GitHub Drive & On-Demand Cache)")
tools_app = typer.Typer(help="🛠 Quản lý Toolchains ngoại vi (IDA Pro MCP, Ghidra, v.v.)")

app.add_typer(instance_app, name="instance")
app.add_typer(env_app, name="env")
app.add_typer(advisor_app, name="advisor")
app.add_typer(meta_app, name="meta")
app.add_typer(prompt_app, name="prompt")
app.add_typer(cleanup_app, name="cleanup")
app.add_typer(knowledge_app, name="knowledge")
app.add_typer(tools_app, name="tools")

console = Console()

def _resolve_workspace(workspace: Optional[Path] = None) -> Path:
    if workspace:
        return workspace.resolve()
    cfg = load_config()
    if cfg.workspace_dir:
        p = Path(cfg.workspace_dir).resolve()
        if p.is_dir():
            return p
    found_env = find_env_file()
    if found_env:
        return found_env.parent.resolve()
    return Path.cwd().resolve()

# ==============================================================================
# TOP-LEVEL CORE COMMANDS
# ==============================================================================

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
    target_url = url or cfg.platform_url
    if not target_url:
        console.print("[bold red]❌ Chưa cấu hình platform_url trong .env hoặc cờ --url![/bold red]")
        raise typer.Exit(code=1)

    p_type = detect_platform_type(target_url, cookie or cfg.session_cookie)
    platform = create_platform(p_type, target_url, cookie or cfg.session_cookie, token or cfg.api_token)

    try:
        challenges = platform.list_challenges()
    except Exception as e:
        console.print(f"[bold red]❌ Lỗi khi lấy danh sách bài từ platform:[/bold red] {e}")
        raise typer.Exit(code=1)

    if category:
        cat_lower = category.lower()
        challenges = [c for c in challenges if (c.category or "").lower() == cat_lower]

    table = Table(title=f"📋 Danh sách Challenges ({len(challenges)} bài)", header_style="bold cyan")
    table.add_column("ID", width=6)
    table.add_column("Category", width=12)
    table.add_column("Tên bài", width=30)
    table.add_column("Điểm", justify="right", width=8)
    table.add_column("Trạng thái", justify="center", width=12)

    for ch in challenges:
        status_str = "[bold green]✔ Solved[/bold green]" if ch.solved_by_me else "[dim]Chưa giải[/dim]"
        table.add_row(str(ch.id), ch.category or "Misc", ch.name, str(ch.points or 0), status_str)

    console.print(table)


@app.command(name="pull")
def pull_cmd(
    all_challs: bool = typer.Option(False, "--all", "-a", help="Preload và tải toàn bộ attachments của cả giải"),
    category: Optional[str] = typer.Option(None, "--category", "-C", help="Lọc theo category"),
    url: Optional[str] = typer.Option(None, "--url", "-u", help="Platform URL"),
    cookie: Optional[str] = typer.Option(None, "--cookie", "-c", help="Session cookie"),
    token: Optional[str] = typer.Option(None, "--token", "-t", help="API token"),
):
    """
    Đồng bộ danh sách challenge từ platform vào bộ nhớ cache runtime (.runtime/<event>/event.json).
    Mặc định LAZY: không tạo thư mục hay tải toàn bộ tệp đính kèm trừ khi dùng cờ --all.
    """
    cfg = load_config()
    target_url = url or cfg.platform_url
    if not target_url:
        console.print("[bold red]❌ Chưa cấu hình platform_url trong .env hoặc cờ --url![/bold red]")
        raise typer.Exit(code=1)

    puller = PullService(
        output_dir=Path.cwd(),
        category=category,
        url=target_url,
        session_cookie=cookie or cfg.session_cookie,
        api_token=token or cfg.api_token,
        preload_all=all_challs,
    )
    result = puller.execute()
    challs = result.challenges if hasattr(result, "challenges") else result.get("challenges", [])
    console.print(f"[bold green]✔ Đã đồng bộ thành công metadata của {len(challs)} bài thi vào runtime cache![/bold green]")


@app.command(name="auto")
def auto_cmd(
    category: Optional[str] = typer.Option(None, "--category", "-C", help="Chỉ giải bài thuộc category cụ thể"),
    max_iter: int = typer.Option(5, "--max-iter", "-m", help="Số vòng lặp ReAct tối đa cho mỗi bài"),
    executor_mode: str = typer.Option("auto", "--executor", "-e", help="Chế độ thực thi: 'auto', 'container', 'restricted', 'unsafe-local'"),
    allow_fallback: bool = typer.Option(False, "--allow-local-fallback", help="Cho phép chạy trên host nếu không có container engine (nguy hiểm)"),
    allow_net: bool = typer.Option(False, "--allow-network", help="Cho phép container truy cập network bridge cho remote challenges"),
    url: Optional[str] = typer.Option(None, "--url", "-u", help="Platform URL"),
    cookie: Optional[str] = typer.Option(None, "--cookie", "-c", help="Session cookie"),
    token: Optional[str] = typer.Option(None, "--token", "-t", help="API token"),
):
    """
    Quy trình tự động hóa khép kín hoàn chỉnh (Closed-Loop Autonomous Solver):
    1. Query platform challenges (lazy)
    2. Chọn bài (ưu tiên điểm thấp nhất)
    3. Materialize runtime tạm thời (.runtime/<event>/challenges/<id>/)
    4. Vòng lặp ReAct: Advisor Guidance -> Executor -> Report Execution
    5. Phát hiện cờ -> Validate -> Nộp cờ ngay lập tức -> Ghi nhận Thẻ Tri Thức -> Dọn dẹp runtime
    """
    ws_dir = _resolve_workspace()
    orchestrator = ChallengeOrchestrator(
        workspace_dir=ws_dir,
        category=category,
        platform_url=url,
        session_cookie=cookie,
        api_token=token,
        max_iterations_per_chall=max_iter,
        cleanup_policy="immediate",
        executor_mode=executor_mode,
        allow_local_fallback=allow_fallback,
        allow_network=allow_net,
    )
    orchestrator.run_tournament_loop()



@app.command(name="solve")
def solve_cmd(
    challenge_id: str = typer.Argument(..., help="ID bài tập cần giải"),
    max_iter: int = typer.Option(5, "--max-iter", "-m", help="Số vòng lặp ReAct tối đa"),
    executor_mode: str = typer.Option("auto", "--executor", "-e", help="Chế độ thực thi: 'auto', 'container', 'restricted-local', 'unsafe-local'"),
    allow_fallback: bool = typer.Option(False, "--allow-local-fallback", help="Cho phép chạy trên host nếu không có container engine (nguy hiểm)"),
    allow_net: bool = typer.Option(False, "--allow-network", help="Cho phép container truy cập network bridge cho remote challenges"),
    url: Optional[str] = typer.Option(None, "--url", "-u", help="Platform URL"),
    cookie: Optional[str] = typer.Option(None, "--cookie", "-c", help="Session cookie"),
    token: Optional[str] = typer.Option(None, "--token", "-t", help="API token"),
):
    """
    Chạy bộ điều phối giải tự động cho 1 bài thi cụ thể (Closed-Loop ReAct Cycle).
    """
    ws_dir = _resolve_workspace()
    orchestrator = ChallengeOrchestrator(
        workspace_dir=ws_dir,
        platform_url=url,
        session_cookie=cookie,
        api_token=token,
        max_iterations_per_chall=max_iter,
        cleanup_policy="immediate",
        executor_mode=executor_mode,
        allow_local_fallback=allow_fallback,
        allow_network=allow_net,
    )
    rt = RuntimeManager()
    state = rt.read_challenge_state(orchestrator.event_id, challenge_id)
    if state and state.get("solved_by_me"):
        console.print(f"[bold green]✔ ALREADY_SOLVED: Bài ID {challenge_id} đã được giải quyết thành công trước đó.[/bold green]")
        return

    challs = orchestrator.sync_challenges(download_attachments=False)
    target = None
    for c in challs:
        if str(c.get("id")) == str(challenge_id):
            target = c
            break

    if not target:
        # Check if already materialized in runtime for RUNTIME_ONLY_RESUME
        chall_path = rt.challenge_path(orchestrator.event_id, challenge_id)
        if chall_path.is_dir() and state:
            console.print(f"[cyan]⚡ RUNTIME_ONLY_RESUME: Tiếp tục giải bài ID {challenge_id} từ ephemeral runtime đã dựng sẵn.[/cyan]")
            target = {
                "id": challenge_id,
                "name": state.get("name") or state.get("challenge_name") or f"Challenge_{challenge_id}",
                "category": state.get("category", "Misc"),
                "points": state.get("points", 0),
                "connection_info": state.get("connection_info", ""),
            }
        else:
            if orchestrator.platform and hasattr(orchestrator.platform, "authenticated") and not orchestrator.platform.authenticated:
                console.print(f"[bold red]❌ AUTH_FAILED: Không thể xác thực với CTF Platform để tìm bài ID '{challenge_id}'.[/bold red]")
            else:
                console.print(f"[bold red]❌ NOT_FOUND: Bài ID '{challenge_id}' không tồn tại trên platform và chưa được dựng trong runtime.[/bold red]")
            raise typer.Exit(code=1)

    solved = orchestrator.execute_challenge_cycle(target)
    if solved:
        console.print(f"[bold green]✔ Bài ID {challenge_id} đã được giải quyết thành công![/bold green]")
    else:
        console.print(f"[yellow]⏳ Bài ID {challenge_id} chưa giải xong hoặc đang chờ chỉ dẫn thủ công.[/yellow]")



@app.command(name="status")
def status_cmd():
    """
    Xem trạng thái runtime hiện tại trong .runtime/.
    """
    rt = RuntimeManager()
    events = rt.list_events()
    if not events:
        console.print("[yellow]ℹ Không có event runtime active trong .runtime/. Hãy chạy `ctf list` hoặc `ctf solve <id>` để bắt đầu.[/yellow]")
        return

    for ev in events:
        epath = rt.event_path(ev)
        challs = rt.list_materialized_challenges(ev)
        total = len(challs)
        solved = sum(1 for c in challs if c.get("solved_by_me"))
        console.print(Panel(
            f"Event ID: [bold cyan]{ev}[/bold cyan]\n"
            f"Path: {epath}\n"
            f"Materialized Challenges: [bold yellow]{total}[/bold yellow] (Solved: [bold green]{solved}[/bold green])",
            title=f"🎯 RUNTIME EVENT: {ev}",
            border_style="cyan"
        ))
        if challs:
            table = Table(header_style="bold magenta")
            table.add_column("ID", width=6)
            table.add_column("Category", width=12)
            table.add_column("Tên bài", width=30)
            table.add_column("Trạng thái", justify="center", width=14)
            for c in challs:
                st = "[bold green]✔ Solved[/bold green]" if c.get("solved_by_me") else "[dim]⏳ In Progress[/dim]"
                table.add_row(str(c.get("challenge_id")), c.get("category", "Misc"), c.get("name", ""), st)
            console.print(table)


@app.command(name="triage")
def triage_cmd(
    challenge_id: str = typer.Argument(..., help="ID của bài thi cần phân tích Fingerprint"),
    event_id: Optional[str] = typer.Option(None, "--event", "-e", help="Event ID"),
):
    """
    🔍 Phân tích Deep Fingerprint (kiến trúc, mitigations, primitives) và gợi ý Thẻ Tri Thức phù hợp.
    """
    rt = RuntimeManager()
    events = rt.list_events()
    ev = event_id or (events[0] if events else "default_event")
    meta = rt.read_challenge_state(ev, challenge_id) or {}
    chall_path = rt.event_path(ev) / "challenges" / str(challenge_id)

    if not chall_path.exists():
        console.print(f"[yellow]⚠️ Challenge runtime chưa materialize tại {chall_path}. Phân tích dựa trên metadata.[/yellow]")
        chall_path = None

    fp = FingerprintEngine.extract(meta, chall_dir=chall_path)

    table = Table(title=f"🎯 Deep Challenge Fingerprint: {meta.get('name', challenge_id)} (ID: {challenge_id})", header_style="bold cyan")
    table.add_column("Thuộc tính", style="bold", width=25)
    table.add_column("Chi tiết", width=55)

    table.add_row("Category", f"[bold green]{fp.category.upper()}[/bold green]")
    table.add_row("File Types", ", ".join(fp.file_types) or "None detected")
    table.add_row("Architectures", ", ".join(fp.architectures) or "None detected")
    table.add_row("Protections (Checksec)", ", ".join(fp.protections) or "None")
    table.add_row("Detected Frameworks", ", ".join(fp.frameworks) or "None")
    table.add_row("Candidate Primitives", ", ".join(fp.primitives) or "None")
    table.add_row("Extracted Keywords", ", ".join(fp.suspicious_patterns[:8]) or "None")
    table.add_row("Confidence", f"{fp.confidence * 100:.0f}%")
    console.print(table)

    # Query Knowledge Provider for top matching cards
    try:
        provider = GitHubKnowledgeProvider(offline=False)
        hits = provider.search(fp.to_knowledge_query(), limit=3)
        if hits:
            ktable = Table(title="📚 Top Reusable Technique Cards từ v0_ctf_knowledge", header_style="bold magenta")
            ktable.add_column("Điểm", justify="right", width=6)
            ktable.add_column("ID", width=30)
            ktable.add_column("Tiêu đề", width=35)
            ktable.add_column("Khớp trên", width=25)
            for h in hits:
                ktable.add_row(f"{h.score:.1f}", h.id, h.title, ", ".join(h.matched_on))
            console.print(ktable)
    except Exception:
        pass


@app.command(name="submit")
def submit_cmd(
    challenge_id: str = typer.Argument(..., help="ID bài tập cần nộp flag"),
    flag: str = typer.Argument(..., help="Chuỗi flag cần nộp"),
    strict: bool = typer.Option(True, "--strict/--no-strict", help="Kiểm tra format flag nghiêm ngặt"),
    url: Optional[str] = typer.Option(None, "--url", "-u", help="Platform URL"),
    cookie: Optional[str] = typer.Option(None, "--cookie", "-c", help="Session cookie"),
    token: Optional[str] = typer.Option(None, "--token", "-t", help="API token"),
):
    """
    Nộp flag tức thì ('ctf_submit_right_away'). Chống nộp trùng và cảnh báo can thiệp thủ công nếu platform lỗi.
    """
    cfg = load_config()
    target_url = url or cfg.platform_url
    if not target_url:
        console.print("[bold red]❌ Chưa cấu hình platform_url trong .env hoặc cờ --url![/bold red]")
        raise typer.Exit(code=1)

    sub_service = SubmitService(
        platform_url=target_url,
        session_cookie=cookie or cfg.session_cookie,
        api_token=token or cfg.api_token,
        flag_format=cfg.flag_format,
    )
    result = sub_service.submit(challenge_id=challenge_id, flag=flag, strict=strict)
    if result.verdict not in ["correct", "already_solved"]:
        raise typer.Exit(code=1)


@app.command(name="pending")
def pending_cmd():
    """
    Liệt kê các bài tập chưa được giải quyết trong runtime.
    """
    rt = RuntimeManager()
    events = rt.list_events()
    unsolved = []
    for ev in events:
        for c in rt.list_materialized_challenges(ev):
            if not c.get("solved_by_me"):
                unsolved.append(c)

    if not unsolved:
        console.print("[green]✔ Không có bài nào chưa giải trong runtime active![/green]")
        return

    table = Table(title=f"⏳ Danh sách bài chưa giải ({len(unsolved)} bài)", header_style="bold yellow")
    table.add_column("ID", width=6)
    table.add_column("Category", width=12)
    table.add_column("Tên bài", width=30)
    for u in unsolved:
        table.add_row(str(u.get("challenge_id")), u.get("category", "Misc"), u.get("name", ""))
    console.print(table)

# ==============================================================================
# SUB-APPS: INSTANCE
# ==============================================================================

@instance_app.command(name="start")
def instance_start_cmd(
    challenge_id: str = typer.Argument(..., help="ID bài tập cần khởi tạo container"),
    url: Optional[str] = typer.Option(None, "--url", "-u", help="Platform URL"),
    cookie: Optional[str] = typer.Option(None, "--cookie", "-c", help="Session cookie"),
    token: Optional[str] = typer.Option(None, "--token", "-t", help="API token"),
):
    cfg = load_config()
    target_url = url or cfg.platform_url
    service = InstanceService(
        platform_url=target_url,
        session_cookie=cookie or cfg.session_cookie,
        api_token=token or cfg.api_token,
    )
    service.start(challenge_id)


@instance_app.command(name="stop")
def instance_stop_cmd(
    challenge_id: str = typer.Argument(..., help="ID bài tập cần dừng container"),
    url: Optional[str] = typer.Option(None, "--url", "-u", help="Platform URL"),
    cookie: Optional[str] = typer.Option(None, "--cookie", "-c", help="Session cookie"),
    token: Optional[str] = typer.Option(None, "--token", "-t", help="API token"),
):
    cfg = load_config()
    target_url = url or cfg.platform_url
    service = InstanceService(
        platform_url=target_url,
        session_cookie=cookie or cfg.session_cookie,
        api_token=token or cfg.api_token,
    )
    service.stop(challenge_id)


@instance_app.command(name="extend")
def instance_extend_cmd(
    challenge_id: str = typer.Argument(..., help="ID bài tập cần gia hạn"),
    url: Optional[str] = typer.Option(None, "--url", "-u", help="Platform URL"),
    cookie: Optional[str] = typer.Option(None, "--cookie", "-c", help="Session cookie"),
    token: Optional[str] = typer.Option(None, "--token", "-t", help="API token"),
):
    cfg = load_config()
    target_url = url or cfg.platform_url
    service = InstanceService(
        platform_url=target_url,
        session_cookie=cookie or cfg.session_cookie,
        api_token=token or cfg.api_token,
    )
    service.extend(challenge_id)

# ==============================================================================
# SUB-APPS: ADVISOR
# ==============================================================================

@advisor_app.command(name="init")
def advisor_init_cmd(challenge_id: str = typer.Argument(..., help="ID bài tập")):
    adv = AdvisorService()
    adv.init_challenge_advisor(challenge_id)
    console.print(f"[bold green]✔ Đã khởi tạo cấu trúc .advisor/ cho Challenge ID: {challenge_id}[/bold green]")


@advisor_app.command(name="consult")
def advisor_consult_cmd(
    challenge_id: str = typer.Argument(..., help="ID bài tập"),
    instruction: Optional[str] = typer.Option(None, "--instruction", "-i", help="Chỉ dẫn bổ sung cho Advisor"),
):
    adv = AdvisorService()
    res = adv.consult(challenge_id, extra_instruction=instruction)
    status = res.get("status")
    if status == "WAITING_FOR_MANUAL_RESPONSE":
        console.print(f"[bold yellow]⏸ Prompt đã được sao chép vào Clipboard và mở Firefox. Hãy dán câu trả lời vào .advisor/guidance.md hoặc chạy `ctf advisor import-response {challenge_id} <file>`![/bold yellow]")
    else:
        console.print(f"[bold green]✔ Đã nhận hướng dẫn chiến lược từ Strategic Advisor![/bold green]")


@advisor_app.command(name="import-response")
def advisor_import_cmd(
    challenge_id: str = typer.Argument(..., help="ID bài tập"),
    file: Path = typer.Argument(..., help="Tệp markdown chứa phản hồi từ ChatGPT Web"),
):
    """
    Nhập phản hồi thủ công từ ChatGPT Web vào Advisor DAG sau khi Firefox fallback.
    """
    if not file.is_file():
        console.print(f"[bold red]❌ Tệp không tồn tại: {file}[/bold red]")
        raise typer.Exit(code=1)

    content = file.read_text(encoding="utf-8")
    adv = AdvisorService()
    res = adv.import_manual_response(challenge_id, content)
    console.print(f"[bold green]✔ Đã nạp thành công phản hồi cố vấn cho Challenge ID {challenge_id}![/bold green]")
    if res.guidance and res.guidance.hypotheses:
        console.print(f"  → Giả thuyết kích hoạt: [cyan]{res.guidance.hypotheses[0].statement}[/cyan]")


@advisor_app.command(name="resume")
def advisor_resume_cmd(challenge_id: str = typer.Argument(..., help="ID bài tập cần tiếp tục giải")):
    """
    Tiếp tục chu trình Closed-Loop Solver sau khi đã nhập phản hồi cố vấn.
    """
    ws_dir = _resolve_workspace()
    orchestrator = ChallengeOrchestrator(workspace_dir=ws_dir)
    orchestrator.execute_challenge_cycle({"id": challenge_id, "name": f"Challenge_{challenge_id}", "category": "Misc"})

# ==============================================================================
# SUB-APPS: KNOWLEDGE
# ==============================================================================

@knowledge_app.command(name="sync")
def knowledge_sync_cmd(
    repo: str = typer.Option("DangGPhuc/v0_ctf_knowledge", "--repo", "-r", help="GitHub repository"),
    ref: str = typer.Option("main", "--ref", help="Branch / Tag"),
):
    """
    Đồng bộ mục lục Thẻ Tri Thức từ GitHub (Drive mode) vào cache cục bộ.
    """
    provider = GitHubKnowledgeProvider(repo=repo, ref=ref)
    ok = provider.sync_index()
    if ok:
        console.print("[bold green]✔ Đồng bộ mục lục tri thức thành công![/bold green]")
    else:
        console.print("[yellow]⚠️ Đồng bộ thất bại hoặc đang ở chế độ offline.[/yellow]")


@knowledge_app.command(name="search")
def knowledge_search_cmd(
    query: str = typer.Argument(..., help="Từ khóa tìm kiếm (primitive, kĩ thuật, format, CVE)"),
    category: Optional[str] = typer.Option(None, "--category", "-C", help="Lọc theo category"),
    limit: int = typer.Option(5, "--limit", "-l", help="Số lượng kết quả tối đa"),
    offline: bool = typer.Option(False, "--offline", help="Chỉ tìm kiếm trong cache cục bộ"),
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="GitHub repository"),
    ref: Optional[str] = typer.Option(None, "--ref", help="Branch / Tag"),
):
    """
    Tìm kiếm Thẻ Tri Thức bằng thuật toán tính điểm deterministic (category, tags, keywords).
    """
    kwargs = {"offline": offline}
    if repo:
        kwargs["repo"] = repo
    if ref:
        kwargs["ref"] = ref
    provider = GitHubKnowledgeProvider(**kwargs)
    kq = KnowledgeQuery(category=category, keywords=query.split())
    hits = provider.search(kq, limit=limit)

    if not hits:
        console.print(f"[yellow]ℹ Không tìm thấy thẻ tri thức nào phù hợp với query: '{query}'[/yellow]")
        return

    table = Table(title=f"📚 Kết Quả Tìm Kiếm Tri Thức ({len(hits)} hits)", header_style="bold green")
    table.add_column("Điểm", justify="right", width=6)
    table.add_column("ID", width=25)
    table.add_column("Tên Thẻ", width=30)
    table.add_column("Khớp Trên", width=30)

    for h in hits:
        table.add_row(f"{h.score:.1f}", h.id, h.title or h.id, ", ".join(h.matched_on))
    console.print(table)


@knowledge_app.command(name="fetch")
def knowledge_fetch_cmd(
    card_id: str = typer.Argument(..., help="ID của thẻ tri thức cần tải"),
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="GitHub repository"),
    ref: Optional[str] = typer.Option(None, "--ref", help="Branch / Tag"),
):
    """
    Tải nội dung chi tiết của một Thẻ Tri Thức từ remote GitHub vào cache và hiển thị.
    """
    kwargs = {}
    if repo:
        kwargs["repo"] = repo
    if ref:
        kwargs["ref"] = ref
    provider = GitHubKnowledgeProvider(**kwargs)
    doc = provider.fetch(card_id)
    if not doc:
        console.print(f"[bold red]❌ Không tìm thấy thẻ tri thức: {card_id}[/bold red]")
        raise typer.Exit(code=1)

    console.print(Panel(
        f"[bold cyan]{doc.title}[/bold cyan] ({doc.category})\n\n"
        f"**Tóm tắt**: {doc.summary}\n\n"
        f"**Dấu hiệu (Signals)**:\n" + "\n".join(f"- {s}" for s in doc.signals) + "\n\n"
        f"**Kĩ thuật thực thi**:\n" + "\n".join(f"{idx}. {step}" for idx, step in enumerate(doc.technique_steps, 1)),
        title=f"📖 {doc.id}",
        border_style="green"
    ))


@knowledge_app.command(name="cache-clean")
def knowledge_cache_clean_cmd():
    """
    Xóa sạch bộ nhớ đệm tri thức cục bộ ~/.cache/v0_ctf_solver/knowledge/.
    """
    cache = KnowledgeCache()
    cache.clean()
    console.print("[bold green]✔ Đã xóa sạch cache tri thức![/bold green]")


@knowledge_app.command(name="candidates")
def knowledge_candidates_cmd():
    """
    Liệt kê các thẻ tri thức ứng viên đang chờ trong Local Outbox (~/.local/state/v0_ctf_solver/knowledge-outbox/).
    """
    outbox = KnowledgeOutbox()
    cands = outbox.list_candidates()
    if not cands:
        console.print("[green]✔ Hộp thư đi (Outbox) trống. Chưa có ứng viên tri thức mới nào cần duyệt.[/green]")
        return

    table = Table(title=f"📥 Danh sách Ứng Viên Tri Thức ({len(cands)} bài)", header_style="bold yellow")
    table.add_column("ID", width=25)
    table.add_column("Category", width=12)
    table.add_column("Tên bài", width=30)
    for c in cands:
        table.add_row(c.get("id", ""), c.get("category", ""), c.get("title", ""))
    console.print(table)


@knowledge_app.command(name="validate")
def knowledge_validate_cmd(candidate_path: Path = typer.Argument(..., help="Đường dẫn file YAML ứng viên")):
    """
    Kiểm tra chất lượng và an toàn của một thẻ ứng viên trước khi xuất bản.
    """
    outbox = KnowledgeOutbox()
    errs = outbox.validate_candidate(candidate_path)
    if errs:
        console.print(f"[bold red]❌ Phát hiện {len(errs)} lỗi chất lượng/bảo mật:[/bold red]")
        for e in errs:
            console.print(f"  - {e}")
        raise typer.Exit(code=1)
    console.print("[bold green]✔ Thẻ ứng viên đạt tiêu chuẩn chất lượng và an toàn tuyệt đối![/bold green]")


@knowledge_app.command(name="doctor")
def knowledge_doctor_cmd(
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="GitHub repository"),
    ref: Optional[str] = typer.Option(None, "--ref", help="Branch / Tag"),
):
    """
    Kiểm tra toàn diện tình trạng kết nối, xác thực và bộ đệm của Remote Knowledge Repository.
    """
    kwargs = {}
    if repo:
        kwargs["repo"] = repo
    if ref:
        kwargs["ref"] = ref
    provider = GitHubKnowledgeProvider(**kwargs)
    doc = provider.check_doctor()

    table = Table(title="🏥 Knowledge Subsystem Diagnostics", header_style="bold cyan")
    table.add_column("Thuộc tính", style="bold", width=25)
    table.add_column("Giá trị", width=50)

    table.add_row("Provider", doc["provider"])
    table.add_row("Repository", doc["repo"])
    table.add_row("Branch / Ref", doc["ref"])
    table.add_row("Authenticated", "[green]YES (Token active)[/green]" if doc["authenticated"] else "[yellow]NO (Public / unauthenticated only)[/yellow]")
    table.add_row("Remote Reachable", "[green]YES[/green]" if doc["remote_reachable"] else "[red]NO[/red]")
    table.add_row("Cache Status", f"[cyan]{doc['cache_status'].upper()}[/cyan] (TTL: {doc['ttl_seconds']}s)")
    table.add_row("Index Entry Count", str(doc["index_entry_count"]))
    table.add_row("Last Sync", str(doc["last_sync"]))

    console.print(table)


@knowledge_app.command(name="publish")
def knowledge_publish_cmd(
    candidate_path: Optional[Path] = typer.Argument(None, help="Đường dẫn file YAML ứng viên"),
    all_validated: bool = typer.Option(False, "--all-validated", help="Tự động xuất bản tất cả ứng viên hợp lệ trong outbox"),
):
    """
    Xuất bản thẻ tri thức ứng viên lên v0_ctf_knowledge thông qua Pull Request an toàn.
    KHÔNG BAO GIỜ push trực tiếp lên main.
    """
    import tempfile
    import shutil
    import subprocess
    import yaml

    outbox = KnowledgeOutbox()
    candidates_to_publish: List[Path] = []

    if all_validated:
        cands = outbox.list_candidates()
        if not cands:
            console.print("[yellow]Hộp thư đi trống. Không có ứng viên nào để xuất bản.[/yellow]")
            return
        for c in cands:
            cpath = Path(c.get("file_path", ""))
            if cpath.is_file():
                errs = outbox.validate_candidate(cpath)
                if not errs:
                    candidates_to_publish.append(cpath)
                else:
                    console.print(f"[dim]Bỏ qua ứng viên chưa hợp lệ: {cpath.name}[/dim]")
    elif candidate_path:
        cand_p = Path(candidate_path).resolve()
        if not cand_p.is_file():
            console.print(f"[bold red]❌ Tệp ứng viên không tồn tại: {cand_p}[/bold red]")
            raise typer.Exit(code=1)
        errs = outbox.validate_candidate(cand_p)
        if errs:
            console.print(f"[bold red]❌ Ứng viên không đạt chuẩn chất lượng/an toàn:[/bold red]")
            for e in errs:
                console.print(f"  - {e}")
            raise typer.Exit(code=1)
        candidates_to_publish.append(cand_p)
    else:
        console.print("[bold red]❌ Vui lòng chỉ định đường dẫn tệp ứng viên hoặc sử dụng cờ --all-validated.[/bold red]")
        raise typer.Exit(code=1)

    if not candidates_to_publish:
        console.print("[yellow]Không tìm thấy ứng viên hợp lệ nào để xuất bản.[/yellow]")
        return

    # Check gh CLI
    if not shutil.which("gh"):
        console.print("[bold red]❌ Yêu cầu gh CLI ('gh') để tạo Pull Request.[/bold red]")
        raise typer.Exit(code=1)

    repo_target = "DangGPhuc/v0_ctf_knowledge"
    console.print(f"[bold cyan]🚀 Bắt đầu quy trình xuất bản {len(candidates_to_publish)} ứng viên lên {repo_target}...[/bold cyan]")

    for cand_p in candidates_to_publish:
        try:
            data = yaml.safe_load(cand_p.read_text(encoding="utf-8"))
            cid = data.get("id", cand_p.stem)
            cat = data.get("category", "misc")
            slug = cid.split(".", 1)[-1] if "." in cid else cid
            branch_name = f"knowledge/candidate-{slug}"

            with tempfile.TemporaryDirectory() as tmp_dir:
                tmp_path = Path(tmp_dir)
                console.print(f"[dim]Cloning {repo_target} vào thư mục tạm...[/dim]")
                clone_res = subprocess.run(
                    ["git", "clone", f"https://github.com/{repo_target}.git", str(tmp_path)],
                    capture_output=True, text=True
                )
                if clone_res.returncode != 0:
                    console.print(f"[bold red]❌ Không thể clone repo {repo_target}: {clone_res.stderr}[/bold red]")
                    continue

                # Checkout new branch
                subprocess.run(["git", "checkout", "-b", branch_name], cwd=tmp_path, capture_output=True, check=True)

                # Copy candidate to cards/<category>/<slug>.yaml
                dest_card = tmp_path / "cards" / cat / f"{slug}.yaml"
                dest_card.parent.mkdir(parents=True, exist_ok=True)
                dest_card.write_text(cand_p.read_text(encoding="utf-8"), encoding="utf-8")

                # Rebuild index and validate
                b_res = subprocess.run(["python3", "scripts/build_index.py"], cwd=tmp_path, capture_output=True, text=True)
                v_res = subprocess.run(["python3", "scripts/validate.py"], cwd=tmp_path, capture_output=True, text=True)
                if v_res.returncode != 0:
                    console.print(f"[bold red]❌ Kiểm tra chất lượng repo thất bại:[/bold red]\n{v_res.stdout}\n{v_res.stderr}")
                    continue

                # Commit and push branch
                subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True, check=True)
                subprocess.run(
                    ["git", "commit", "-m", f"feat(knowledge): add {slug} technique candidate"],
                    cwd=tmp_path, capture_output=True, check=True
                )
                push_res = subprocess.run(["git", "push", "-u", "origin", branch_name], cwd=tmp_path, capture_output=True, text=True)
                if push_res.returncode != 0:
                    console.print(f"[bold red]❌ Lỗi push branch {branch_name}: {push_res.stderr}[/bold red]")
                    continue

                # Create PR via gh
                pr_title = f"feat(knowledge): candidate technique {cid}"
                pr_body = (
                    f"## Autonomous Knowledge Candidate Submission\n\n"
                    f"- **ID**: `{cid}`\n"
                    f"- **Category**: `{cat}`\n"
                    f"- **Title**: {data.get('title', cid)}\n\n"
                    f"Generated and validated autonomously via v0_ctf_solver."
                )
                pr_res = subprocess.run(
                    ["gh", "pr", "create", "--repo", repo_target, "--head", branch_name, "--base", "main", "--title", pr_title, "--body", pr_body],
                    cwd=tmp_path, capture_output=True, text=True
                )
                if pr_res.returncode == 0:
                    pr_url = pr_res.stdout.strip()
                    console.print(f"[bold green]✔ Đã tạo PR xuất bản thành công: [cyan]{pr_url}[/cyan][/bold green]")
                else:
                    console.print(f"[yellow]⚠️ Branch {branch_name} đã được push, nhưng tạo PR gặp lỗi: {pr_res.stderr}[/yellow]")

        except Exception as ex:
            console.print(f"[bold red]❌ Lỗi khi xuất bản {cand_p.name}: {ex}[/bold red]")


# ==============================================================================
# SUB-APPS: TOOLS
# ==============================================================================

@tools_app.command(name="list")
def tools_list_cmd():
    """
    Liệt kê các Toolchains ngoại vi có sẵn trong hệ thống (IDA Pro MCP, v.v.).
    """
    tm = ToolManager()
    manifests = tm.list_manifests()
    table = Table(title="🛠 Toolchains & MCP Integrations", header_style="bold cyan")
    table.add_column("ID", width=15)
    table.add_column("Tên Công Cụ", width=30)
    table.add_column("Phiên Bản", width=10)
    table.add_column("Trạng Thái", justify="center", width=12)

    for m in manifests:
        tid = m.get("id", "")
        installed = tm.is_installed(tid)
        st = "[bold green]✔ Installed[/bold green]" if installed else "[dim]Available[/dim]"
        table.add_row(tid, m.get("name", tid), str(m.get("version", "")), st)
    console.print(table)


@tools_app.command(name="doctor")
def tools_doctor_cmd(tool_id: str = typer.Argument("ida-pro-mcp", help="ID công cụ cần kiểm tra")):
    """
    Kiểm tra tình trạng hoạt động và dependencies của một toolchain.
    """
    tm = ToolManager()
    res = tm.check_health(tool_id)
    if res.get("status") == "ok":
        console.print(f"[bold green]✔ Tool {tool_id} đang hoạt động bình thường:[/bold green] {res.get('message')}")
    else:
        console.print(f"[bold red]❌ Tool {tool_id} gặp vấn đề:[/bold red] {res.get('message')}")


@tools_app.command(name="install")
def tools_install_cmd(tool_id: str = typer.Argument(..., help="ID công cụ cần cài đặt")):
    """
    Tải và cài đặt on-demand một toolchain vào ~/.local/share/v0_ctf_solver/tools/.
    """
    tm = ToolManager()
    ok = tm.install(tool_id)
    if not ok:
        raise typer.Exit(code=1)

# ==============================================================================
# SUB-APPS: CLEANUP
# ==============================================================================

@cleanup_app.command(name="challenge")
def cleanup_challenge_cmd(
    challenge_id: str = typer.Argument(..., help="ID challenge cần xóa"),
    event_id: str = typer.Option("default_event", "--event", "-e", help="Event ID"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Chạy thử không xóa file"),
):
    rt = RuntimeManager()
    ok = rt.cleanup_challenge(event_id, challenge_id, dry_run=dry_run)
    if ok:
        console.print(f"[bold green]✔ Đã xóa ephemeral runtime cho Challenge ID: {challenge_id}[/bold green]")
    else:
        console.print(f"[yellow]⚠️ Challenge ID {challenge_id} không tồn tại trong runtime.[/yellow]")


@cleanup_app.command(name="event")
def cleanup_event_cmd(
    event_id: str = typer.Option("default_event", "--event", "-e", help="Event ID cần xóa"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Chạy thử không xóa file"),
):
    rt = RuntimeManager()
    ok = rt.cleanup_event(event_id, dry_run=dry_run)
    if ok:
        console.print(f"[bold green]✔ Đã dọn sạch toàn bộ runtime của event '{event_id}' (Giữ nguyên Knowledge Cards)![/bold green]")


@cleanup_app.command(name="all")
def cleanup_all_cmd(dry_run: bool = typer.Option(False, "--dry-run", help="Chạy thử không xóa file")):
    rt = RuntimeManager()
    ok = rt.cleanup_all(dry_run=dry_run)
    if ok:
        console.print("[bold green]✔ Đã xóa sạch toàn bộ thư mục .runtime/![/bold green]")

if __name__ == "__main__":
    app()
