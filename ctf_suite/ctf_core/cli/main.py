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
advisor_app = typer.Typer(help="🧠 Strategic Advisor Multi-Agent Bridge (Anti-IDE/OpenCode ↔ ChatGPT Web via Oracle/PAL)")
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
        platform_url=target_url,
        session_cookie=cookie or cfg.session_cookie,
        api_token=token or cfg.api_token,
        preload_all=all_challs,
    )
    result = puller.pull()
    console.print(f"[bold green]✔ Đã đồng bộ thành công metadata của {len(result.get('challenges', []))} bài thi vào runtime cache![/bold green]")


@app.command(name="auto")
def auto_cmd(
    category: Optional[str] = typer.Option(None, "--category", "-C", help="Chỉ giải bài thuộc category cụ thể"),
    max_iter: int = typer.Option(5, "--max-iter", "-m", help="Số vòng lặp ReAct tối đa cho mỗi bài"),
    executor_mode: str = typer.Option("auto", "--executor", "-e", help="Chế độ thực thi: 'auto', 'container', 'restricted', 'unsafe-local'"),
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
    )
    orchestrator.run()


@app.command(name="solve")
def solve_cmd(
    challenge_id: str = typer.Argument(..., help="ID bài tập cần giải"),
    max_iter: int = typer.Option(5, "--max-iter", "-m", help="Số vòng lặp ReAct tối đa"),
    executor_mode: str = typer.Option("auto", "--executor", "-e", help="Chế độ thực thi: 'auto', 'container', 'restricted', 'unsafe-local'"),
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
    )
    challs = orchestrator.sync_challenges(download_attachments=False)
    target = None
    for c in challs:
        if str(c.get("id")) == str(challenge_id):
            target = c
            break

    if not target:
        target = {
            "id": challenge_id,
            "name": f"Challenge_{challenge_id}",
            "category": "Misc",
            "points": 100,
        }

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
):
    """
    Tìm kiếm Thẻ Tri Thức bằng thuật toán tính điểm deterministic (category, tags, keywords).
    """
    provider = GitHubKnowledgeProvider(offline=offline)
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
):
    """
    Tải nội dung chi tiết của một Thẻ Tri Thức từ remote GitHub vào cache và hiển thị.
    """
    provider = GitHubKnowledgeProvider()
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
