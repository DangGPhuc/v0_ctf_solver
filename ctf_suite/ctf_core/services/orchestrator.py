import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..config import load_config
from ..models import Challenge, SubmitResult, AdvisorGuidance, ExecutionResult, AdvisorResult
from ..runtime.manager import RuntimeManager, sanitize_path_component
from ..platforms.registry import create_platform, detect_platform_type
from ..execution.adapter import ExecutorAdapter
from ..execution import get_executor
from .submit_service import SubmitService
from .advisor_service import AdvisorService

console = Console()


class ChallengeOrchestrator:
    """
    Closed-Loop Autonomous CTF Orchestrator:
    1. Fetches challenge list lazily from Platform Adapter.
    2. Selects challenge (lowest points first).
    3. Materializes challenge runtime lazily (.runtime/<event-id>/challenges/<id>/).
    4. Downloads attachments on-demand into input/.
    5. Closed-loop loop:
       Advisor.consult() -> AdvisorGuidance
         ↓
       ExecutorAdapter.execute() -> ExecutionResult
         ↓
       Advisor.report_execution()
         ↓
       If flag candidate found: validate -> submit -> correct -> Advisor.mark_solved()
         ↓
       Distill knowledge into KnowledgeCard (no plaintext flags)
         ↓
       Cleanup ephemeral challenge directory according to cleanup policy.
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
        reverse_skill_dir: Optional[Path] = None,
        runtime_manager: Optional[RuntimeManager] = None,
        executor: Optional[ExecutorAdapter] = None,
        event_id: Optional[str] = None,
        cleanup_policy: str = "immediate",  # immediate, event_end, manual
        platform: Optional[Any] = None,
        advisor: Optional[AdvisorService] = None,
        submitter: Optional[SubmitService] = None,
    ):
        self.workspace_dir = Path(workspace_dir).resolve()
        self.category = category.strip() if category else None
        
        cfg = load_config(self.workspace_dir)
        self.platform_url = platform_url or cfg.platform_url
        self.session_cookie = session_cookie or cfg.session_cookie
        self.api_token = api_token or cfg.api_token
        self.flag_format = flag_format or cfg.flag_format or r"^FLAG\{.+\}$"
        self.max_iterations = max_iterations_per_chall
        self.cleanup_policy = cleanup_policy
        
        self.runtime_manager = runtime_manager or RuntimeManager()
        if event_id:
            self.event_id = sanitize_path_component(event_id)
        elif self.platform_url:
            host = urlsplit(self.platform_url).netloc or "ctf_event"
            self.event_id = sanitize_path_component(host)
        else:
            self.event_id = "default_event"

        self.reverse_skill_dir = (
            Path(reverse_skill_dir).resolve()
            if reverse_skill_dir
            else self.workspace_dir.parent / "reverse-skill"
        )
        
        self.platform = platform
        if self.platform is None and self.platform_url:
            p_type = detect_platform_type(self.platform_url, self.session_cookie)
            self.platform = create_platform(
                platform_name=p_type,
                url=self.platform_url,
                session_cookie=self.session_cookie,
                api_token=self.api_token,
            )

        self.submitter = submitter or SubmitService(
            workspace_dir=self.workspace_dir,
            platform_url=self.platform_url or "https://mock.ctf",
            session_cookie=self.session_cookie,
            api_token=self.api_token,
            flag_format=self.flag_format,
            runtime_manager=self.runtime_manager,
            event_id=self.event_id,
            platform=self.platform,
        )
        self.advisor = advisor or AdvisorService(
            workspace_dir=self.workspace_dir,
            reverse_skill_dir=self.reverse_skill_dir,
            runtime_manager=self.runtime_manager,
            event_id=self.event_id,
        )
        self.executor = executor or get_executor(flag_format_regex=self.flag_format)

    def sync_challenges(self, download_attachments: bool = False) -> List[Dict[str, Any]]:
        """Fetch challenges directly from platform adapter without creating eager directories."""
        if not self.platform:
            console.print("[yellow]⚠️ No platform configured, falling back to local runtime state.[/yellow]")
            return self._get_unsolved_challenges()

        try:
            raw_challs = self.platform.list_challenges()
        except Exception:
            raw_challs = self.platform.fetch_challenges()

        target_cat = self.category.lower() if self.category else None
        unsolved: List[Dict[str, Any]] = []

        for ch in raw_challs:
            if ch.solved_by_me:
                continue
            cat = (ch.category or "Misc").strip()
            if target_cat and cat.lower() != target_cat:
                continue

            # Check if solved in runtime state
            st = self.runtime_manager.read_challenge_state(self.event_id, ch.id)
            if st and st.get("solved_by_me"):
                continue

            unsolved.append({
                "id": str(ch.id),
                "name": ch.name,
                "category": cat,
                "points": ch.points,
                "challenge": ch,
            })

        unsolved.sort(key=lambda x: int(x.get("points") or 0))
        return unsolved

    def _get_unsolved_challenges(self) -> List[Dict[str, Any]]:
        """Reads unsolved challenges from runtime state."""
        unsolved = []
        target_cat = self.category.lower() if self.category else None

        for chall_st in self.runtime_manager.list_materialized_challenges(self.event_id):
            if chall_st.get("solved_by_me"):
                continue
            cat = chall_st.get("category", "Misc")
            if target_cat and cat.lower() != target_cat:
                continue
            unsolved.append({
                "id": str(chall_st.get("challenge_id")),
                "name": chall_st.get("name", "Chall"),
                "category": cat,
                "points": chall_st.get("points", 0),
            })

        unsolved.sort(key=lambda x: int(x.get("points") or 0))
        return unsolved

    def execute_challenge_cycle(self, chall_info: Dict[str, Any]) -> bool:
        """
        Executes the closed-loop autonomous cycle for a single challenge:
        1. Lazily materializes runtime for this challenge.
        2. Closed loop: Advisor -> ExecutorAdapter -> ExecutionResult -> report_execution().
        3. On flag found: Submit -> verify -> Advisor.mark_solved() -> Cleanup.
        """
        cid = chall_info["id"]
        cname = chall_info["name"]
        cat = chall_info["category"]
        chall_obj = chall_info.get("challenge")
        
        if not chall_obj:
            chall_obj = Challenge(id=cid, name=cname, category=cat, points=chall_info.get("points", 0))

        console.print(Panel(
            f"[bold cyan]🎯 AUTONOMOUS SOLVER CYCLE FOR:[/bold cyan] [bold yellow]{cname}[/bold yellow] (ID: {cid})\n"
            f"Category  : [bold green]{cat}[/bold green]\n"
            f"Points    : [magenta]{chall_info.get('points', 0)}[/magenta]",
            title="[bold green]⚡ CLOSED-LOOP SOLVER[/bold green]"
        ))

        # 1. Lazy materialization: only materialize this challenge right now
        dl_fn = None
        if self.platform and chall_obj.files:
            dl_fn = lambda dest, c_id=cid: self.platform.download_attachments(c_id, dest)
        cpath = self.runtime_manager.materialize_challenge(self.event_id, chall_obj, download_fn=dl_fn)
        work_dir = cpath / "work"
        input_dir = cpath / "input"

        # 2. Init Advisor
        self.advisor.init_challenge_advisor(cid)

        # 3. Closed-Loop Execution Loop
        for iteration in range(1, self.max_iterations + 1):
            console.print(f"\n[bold magenta]─── [ROUND {iteration}/{self.max_iterations}] STRATEGIC ADVISOR CONSULTATION ───[/bold magenta]")
            
            consult_res = self.advisor.consult(cid)
            status = getattr(consult_res, "status", None) if not isinstance(consult_res, dict) else consult_res.get("status")
            if status == "WAITING_FOR_MANUAL_RESPONSE":
                console.print(Panel(
                    f"[bold yellow]⏸ AWAITING MANUAL STRATEGIC GUIDANCE[/bold yellow]\n\n"
                    f"Challenge: [bold]{cname}[/bold] (ID: {cid})\n"
                    f"The strategic prompt has been copied to your clipboard and Firefox opened.\n"
                    f"Once ChatGPT responds, paste it into:\n"
                    f"  [cyan]{cpath}/.advisor/guidance.md[/cyan]\n"
                    f"or run: [bold cyan]ctf advisor import-response {cid} <response_file>[/bold cyan]\n"
                    f"Then resume with: [bold cyan]ctf solve {cid}[/bold cyan]",
                    title="[bold yellow]✋ MANUAL INTERVENTION REQUIRED[/bold yellow]",
                    border_style="yellow",
                    expand=False,
                ))
                return False

            if isinstance(consult_res, dict):
                guidance: Optional[AdvisorGuidance] = consult_res.get("guidance")
                active_hypo = consult_res.get("active_hypothesis")
            else:
                guidance = getattr(consult_res, "guidance", None)
                active_hypo = guidance.hypotheses[0].statement if guidance and guidance.hypotheses else None

            if not guidance:
                guidance = AdvisorGuidance(
                    assessment=active_hypo or "Explore challenge",
                    hypotheses=[Hypothesis(id="H1", statement=active_hypo or "Analyze binary and service")],
                    next_actions=[Action(type="command", command_or_task="python3 solve.py")],
                    requested_evidence=["Flag output"],
                    stop_conditions=["Flag found"],
                )

            # Build challenge context for executor
            challenge_context = {
                "challenge_id": cid,
                "name": cname,
                "category": cat,
                "work_dir": work_dir,
                "input_dir": input_dir,
                "iteration": iteration,
                "connection_info": chall_obj.connection_info,
            }

            # Execute actions via ExecutorAdapter
            console.print(f"[cyan]⚙ Executing plan via {self.executor.__class__.__name__}...[/cyan]")
            exec_result: ExecutionResult = self.executor.execute(challenge_context, guidance)

            # Report execution results back to Advisor (closed loop ReAct)
            self.advisor.report_execution(cid, exec_result)

            # Check if any candidate flag was uncovered
            if exec_result.flag_candidates:
                for candidate in exec_result.flag_candidates:
                    if self.submitter.validate_format(candidate):
                        console.print(f"[bold green]🎯 Discovered candidate flag: {candidate}[/bold green]")
                        sub_res = self.submitter.submit(cid, candidate, strict=True)
                        if sub_res.verdict in ["correct", "already_solved"]:
                            console.print(f"[bold green]✔ Challenge {cname} SOLVED AND ACCEPTED![/bold green]")
                            # Mark solved on advisor & compile knowledge card
                            self.advisor.mark_solved(cid, candidate)
                            
                            # Cleanup runtime if immediate policy
                            if self.cleanup_policy == "immediate":
                                console.print(f"[dim]🧹 Cleaning up ephemeral runtime for challenge {cid}...[/dim]")
                                self.runtime_manager.cleanup_challenge(self.event_id, cid)
                            return True

            # If metadata marked solved externally
            st = self.runtime_manager.read_challenge_state(self.event_id, cid)
            if st and st.get("solved_by_me"):
                return True

        console.print(f"[yellow]⏳ Challenge {cname} reached max iteration limit ({self.max_iterations}). Keeping runtime for resume.[/yellow]")
        return False

    def run_tournament_loop(self, auto_wait_waves: bool = False, poll_interval: int = 45):
        """Runs tournament solving loop lazily."""
        cat_display = self.category.upper() if self.category else "ALL CATEGORIES"
        console.print(Panel(
            f"[bold cyan]🚀 TOURNAMENT ORCHESTRATOR LAUNCHED[/bold cyan]\n\n"
            f"🎯 Target Category : [bold green]{cat_display}[/bold green]\n"
            f"📁 Runtime Event   : [green].runtime/{self.event_id}[/green]\n"
            f"🌐 Platform URL    : [yellow]{self.platform_url or 'N/A'}[/yellow]\n"
            f"🧹 Cleanup Policy  : [cyan]{self.cleanup_policy}[/cyan]",
            title="[bold green]⚡ CTF TOURNAMENT ENGINE[/bold green]"
        ))

        while True:
            unsolved = self.sync_challenges(download_attachments=False)
            if not unsolved:
                console.print(f"\n[bold green]🎉 All challenges in category [{cat_display}] have been solved or none found![/bold green]")
                if not auto_wait_waves:
                    break
                console.print(f"[dim]⏳ Waiting for new challenge waves... Polling in {poll_interval}s...[/dim]")
                time.sleep(poll_interval)
                continue

            console.print(f"\n[bold cyan]📋 Found {len(unsolved)} unsolved challenge(s) in [{cat_display}]:[/bold cyan]")
            for idx, c in enumerate(unsolved, start=1):
                console.print(f"  {idx}. [bold]{c['name']}[/bold] ({c.get('points', 0)} pts) [dim]ID: {c['id']}[/dim]")

            for c in unsolved:
                solved = self.execute_challenge_cycle(c)
                if solved:
                    console.print(f"[bold green]✔ Finished '{c['name']}'. Moving to next challenge![/bold green]\n")
                else:
                    console.print(f"[yellow]⏩ Postponing '{c['name']}' to attempt next challenge.[/yellow]\n")

            if not auto_wait_waves:
                break
            time.sleep(10)
