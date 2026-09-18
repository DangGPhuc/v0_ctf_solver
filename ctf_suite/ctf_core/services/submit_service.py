import fcntl
import hashlib
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from ..models import SubmitResult
from ..platforms.registry import create_platform, detect_platform_type
from ..workspace.repo import WorkspaceRepo
from ..runtime.manager import RuntimeManager

console = Console()

class SubmitService:
    def __init__(
        self,
        workspace_dir: Path,
        platform_url: str,
        session_cookie: Optional[str] = None,
        api_token: Optional[str] = None,
        flag_format: Optional[str] = None,
        platform_type: Optional[str] = None,
        runtime_manager: Optional[RuntimeManager] = None,
        event_id: Optional[str] = None,
        platform: Optional[Any] = None,
    ):
        self.workspace_dir = Path(workspace_dir).resolve()
        self.flag_format = flag_format or r"^FLAG\{.+\}$"
        self.runtime_manager = runtime_manager or RuntimeManager()
        self.event_id = event_id or "default_event"
        self.repo = WorkspaceRepo(self.workspace_dir)
        
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
        # Place ledger in runtime event directory if available, else workspace
        epath = self.runtime_manager.event_path(self.event_id)
        if epath.exists():
            self.ledger_file = epath / ".submitted_flags.jsonl"
        else:
            self.ledger_file = self.workspace_dir / ".submitted_flags.jsonl"
        self._ensure_secure_file(self.ledger_file)

    def _ensure_secure_file(self, file_path: Path):
        """Ensure file is chmod 0600."""
        if file_path.exists():
            try:
                os.chmod(file_path, 0o600)
            except Exception:
                pass

    def validate_format(self, flag: str) -> bool:
        """
        Validate flag format strictly:
        - Must not contain template placeholders (FLAG{...}, insert_flag, etc.)
        - Must match flag regex
        - Must not contain control/newline characters
        """
        if not flag or not isinstance(flag, str):
            return False
        flag = flag.strip()

        placeholders = ["flag{...}", "null0rigin{...}", "flag_here", "insert_flag", "..."]
        lower_flag = flag.lower()
        if any(p in lower_flag for p in placeholders):
            return False

        if "\n" in flag or "\r" in flag or len(flag) < 5:
            return False

        try:
            return bool(re.fullmatch(self.flag_format, flag))
        except Exception:
            return "{" in flag and flag.endswith("}")

    def _get_flag_hash(self, challenge_id: Any, flag: str) -> str:
        data = f"{challenge_id}:{flag.strip()}".encode("utf-8")
        return hashlib.sha256(data).hexdigest()

    def has_been_submitted(self, challenge_id: Any, flag: str) -> Optional[str]:
        """
        Check whether this flag has already been submitted for challenge_id.
        Treats 'ratelimited', 'auth_failed', and 'error' as retryable.
        Uses file locking for concurrency protection.
        """
        if not self.ledger_file.exists():
            return None

        target_hash = self._get_flag_hash(challenge_id, flag)
        lock_file = self.ledger_file.with_suffix(".lock")
        try:
            with open(lock_file, "w") as lf:
                fcntl.flock(lf.fileno(), fcntl.LOCK_SH)
                try:
                    for line in self.ledger_file.read_text(encoding="utf-8").splitlines():
                        if not line.strip():
                            continue
                        entry = json.loads(line)
                        if entry.get("hash") == target_hash:
                            verdict = entry.get("verdict")
                            # Retryable on temporary failures
                            if verdict not in ["ratelimited", "auth_failed", "error"]:
                                return verdict
                finally:
                    fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass
        return None

    def _record_submission(self, challenge_id: Any, flag: str, result: SubmitResult):
        """Record submission with hash-only and concurrency protection."""
        flag_clean = flag.strip()
        masked = flag_clean[:6] + "..." + flag_clean[-4:] if len(flag_clean) > 12 else "***"
        entry = {
            "timestamp": datetime.now().isoformat(),
            "challenge_id": str(challenge_id),
            "flag_masked": masked,
            "hash": self._get_flag_hash(challenge_id, flag_clean),
            "verdict": result.verdict,
            "message": result.message
        }
        lock_file = self.ledger_file.with_suffix(".lock")
        try:
            with open(lock_file, "w") as lf:
                fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
                try:
                    with open(self.ledger_file, "a", encoding="utf-8") as f:
                        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
                    self._ensure_secure_file(self.ledger_file)
                finally:
                    fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass

    def submit(self, challenge_id: Any, flag: str, strict: bool = False) -> SubmitResult:
        flag = flag.strip()
        chall_name = f"ID: {challenge_id}"
        
        # Check runtime state first
        st = self.runtime_manager.read_challenge_state(self.event_id, challenge_id)
        if st and st.get("name"):
            chall_name = f"{st.get('name')} (ID: {challenge_id})"
        else:
            chall_dir = self.repo.find_challenge_dir(challenge_id)
            if chall_dir:
                meta = self.repo.read_challenge_metadata(chall_dir) or {}
                chall_name = f"{meta.get('name', '')} (ID: {challenge_id})"

        console.print(f"[bold cyan]🚩 Processing flag submission for [yellow]{chall_name}[/yellow]...[/bold cyan]")

        # 1. Validate format
        is_valid = self.validate_format(flag)
        if not is_valid:
            if strict:
                console.print(f"[bold red]❌ SUBMISSION REJECTED: Flag '{flag}' does not match format '{self.flag_format}' or is a placeholder![/bold red]")
                return SubmitResult(
                    verdict="invalid_format",
                    message=f"Flag does not match format '{self.flag_format}'.",
                    challenge_id=challenge_id,
                    challenge_name=chall_name,
                    flag=flag
                )
            else:
                console.print(f"[bold yellow]⚠️ Warning: Flag '{flag}' does not match format '{self.flag_format}'![/bold yellow]")

        # 2. Concurrency-protected Deduplication
        prev_verdict = self.has_been_submitted(challenge_id, flag)
        if prev_verdict:
            console.print(f"[dim]⚡ Skipping: Flag has already been submitted with verdict [{prev_verdict}].[/dim]")
            return SubmitResult(
                verdict=prev_verdict,
                message=f"Flag already submitted previously (Verdict: {prev_verdict}).",
                challenge_id=challenge_id,
                challenge_name=chall_name,
                flag=flag
            )

        # 3. Submit to platform
        result = self.platform.submit_flag(challenge_id, flag)
        result.challenge_name = chall_name

        # 4. Record to ledger
        self._record_submission(challenge_id, flag, result)

        # 5. Handle result
        if result.verdict in ["correct", "already_solved"]:
            if result.verdict == "correct":
                console.print(Panel(
                    Text.assemble(
                        ("🎉 CONGRATULATIONS! CHALLENGE SOLVED!\n\n", "bold green"),
                        ("Challenge : ", "bold"), (f"{chall_name}\n", "cyan"),
                        ("Flag      : ", "bold"), (f"{flag}\n", "bold yellow"),
                        ("Message   : ", "bold"), (f"{result.message}\n", "green"),
                    ),
                    title="[bold green]✔ FLAG ACCEPTED[/bold green]",
                    border_style="green",
                    expand=False
                ))
            else:
                console.print(f"[cyan]ℹ Challenge {chall_name} was already marked solved on the platform.[/cyan]")

            # Update runtime state
            self.runtime_manager.update_challenge_state(
                self.event_id,
                challenge_id,
                lambda d: {**d, "solved_by_me": True, "status": "solved", "flag": flag}
            )
            # Update legacy repo if exists
            self.repo.mark_challenge_solved(challenge_id, flag)
            return result

        # 6. Failure handling
        self._display_manual_intervention_alert(chall_name, challenge_id, flag, result)
        self._log_failed_flag(challenge_id, chall_name, flag, result.message)
        return result

    def auto_scan_and_submit(self) -> List[SubmitResult]:
        """Scan workspace and runtime challenges for new flag.txt files."""
        console.print("[cyan]🔍 Scanning for new flags...[/cyan]")
        results: List[SubmitResult] = []

        # Scan runtime challenges
        for chall in self.runtime_manager.list_materialized_challenges(self.event_id):
            cid = chall.get("challenge_id")
            if not cid or chall.get("solved_by_me"):
                continue
            cpath = self.runtime_manager.challenge_path(self.event_id, cid)
            flag_p = cpath / "work" / "flag.txt"
            if flag_p.is_file():
                content = flag_p.read_text(encoding="utf-8").strip()
                if content and self.validate_format(content):
                    res = self.submit(cid, content, strict=True)
                    results.append(res)

        # Fallback to legacy workspace scan if needed
        for cdir in self.repo.iter_challenge_dirs():
            meta = self.repo.read_challenge_metadata(cdir) or {}
            if meta.get("solved_by_me"):
                continue
            cid = meta.get("id")
            for p in [cdir / "solver" / "flag.txt", cdir / "challenge" / "flag.txt", cdir / "flag.txt"]:
                if p.is_file():
                    content = p.read_text(encoding="utf-8").strip()
                    if content and self.validate_format(content) and cid is not None:
                        res = self.submit(cid, content, strict=True)
                        results.append(res)
                        break

        return results

    def _display_manual_intervention_alert(
        self,
        chall_name: str,
        challenge_id: Any,
        flag: str,
        result: SubmitResult
    ):
        alert_text = Text.assemble(
            ("⚠️ WARNING: FLAG SUBMISSION FAILED ON PLATFORM!\n\n", "bold red"),
            ("Challenge  : ", "bold"), (f"{chall_name}\n", "white"),
            ("Flag       : ", "bold"), (f"{flag}\n", "bold yellow"),
            ("Reason     : ", "bold"), (f"[{result.verdict.upper()}] {result.message}\n\n", "red"),
            ("👉 PLEASE COPY THE FLAG ABOVE AND SUBMIT MANUALLY IN YOUR BROWSER!\n", "bold bright_yellow")
        )
        console.print(Panel(
            alert_text,
            title="[bold red]🚨 MANUAL INTERVENTION REQUIRED[/bold red]",
            border_style="red",
            expand=False
        ))

    def _log_failed_flag(self, cid: Any, cname: str, flag: str, reason: str):
        epath = self.runtime_manager.event_path(self.event_id)
        log_file = epath / ".failed_flags.log" if epath.exists() else self.workspace_dir / ".failed_flags.log"
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"[{now}] Challenge: {cname} (ID: {cid}) | Flag: {flag} | Reason: {reason}\n")
        self._ensure_secure_file(log_file)
