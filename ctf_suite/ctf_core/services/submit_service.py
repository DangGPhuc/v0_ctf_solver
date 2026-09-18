import fcntl
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from ..models import SubmitResult
from ..platforms.registry import create_platform, detect_platform_type
from ..runtime.manager import RuntimeManager

console = Console()

class SubmitService:
    def __init__(
        self,
        platform_url: Optional[str] = None,
        session_cookie: Optional[str] = None,
        api_token: Optional[str] = None,

        flag_format: Optional[str] = None,
        platform_type: Optional[str] = None,
        runtime_manager: Optional[RuntimeManager] = None,
        event_id: Optional[str] = None,
        platform: Optional[Any] = None,
        workspace_dir: Optional[Path] = None,  # Kept for backward compatibility
    ):
        self.flag_format = flag_format or r"^FLAG\{.+\}$"
        if runtime_manager is not None:
            self.runtime_manager = runtime_manager
        elif workspace_dir is not None:
            self.runtime_manager = RuntimeManager(base_dir=Path(workspace_dir) / ".runtime")
        else:
            self.runtime_manager = RuntimeManager()
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
        
        # Ensure event path exists in runtime
        epath = self.runtime_manager.event_path(self.event_id)
        if not epath.exists():
            self.runtime_manager.start_event(self.event_id)
            
        self.ledger_file = epath / ".submitted_flags.jsonl"
        self._ensure_secure_file(self.ledger_file)

    def _ensure_secure_file(self, file_path: Path):
        """Ensure file is chmod 0600."""
        if file_path.exists():
            try:
                os.chmod(file_path, 0o600)
            except Exception:
                pass

    def validate_format(self, flag: str) -> bool:
        """Validate flag format strictly."""
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
        except re.error:
            return "{" in flag and flag.endswith("}")

    def _hash_flag(self, challenge_id: Any, flag: str) -> str:
        """Hash challenge_id and flag for deduplication without storing plaintext in disk ledger."""
        return hashlib.sha256(f"{challenge_id}:{flag.strip()}".encode("utf-8")).hexdigest()

    def _mask_flag(self, flag: str) -> str:
        """Mask flag string for safe display/logging."""
        flag = flag.strip()
        if len(flag) <= 8:
            return "***"
        prefix = flag[:5]
        suffix = flag[-2:]
        return f"{prefix}***{suffix}"

    def has_been_submitted(self, challenge_id: Any, flag: str) -> Optional[str]:
        """
        Check if (challenge_id, flag) has been submitted.
        Returns the previous verdict if it was a final verdict, or None if retryable.
        """
        if not self.ledger_file.exists():
            return None

        target_hash = self._hash_flag(challenge_id, flag)
        lock_file = self.ledger_file.with_suffix(".lock")
        try:
            with open(lock_file, "w") as lf:
                fcntl.flock(lf.fileno(), fcntl.LOCK_SH)
                try:
                    latest_verdict = None
                    for line in self.ledger_file.read_text(encoding="utf-8").splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            record = json.loads(line)
                            if record.get("hash") == target_hash or record.get("flag_hash") == target_hash:
                                v = record.get("verdict")
                                if v in ["ratelimited", "auth_failed", "error", "invalid_format"]:
                                    latest_verdict = None
                                else:
                                    latest_verdict = v
                        except json.JSONDecodeError:
                            continue
                    return latest_verdict
                finally:
                    fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass

        return None

    def _record_submission(self, challenge_id: Any, flag: str, result: SubmitResult):
        """Append submission event to .submitted_flags.jsonl."""
        flag_clean = flag.strip()
        h = self._hash_flag(challenge_id, flag_clean)
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "challenge_id": str(challenge_id),
            "challenge_name": result.challenge_name,
            "flag_masked": self._mask_flag(flag_clean),
            "hash": h,
            "flag_hash": h,
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
    def submit_right_away(self, challenge_id: Any, flag: str, strict: bool = False) -> SubmitResult:
        """Alias for submit() adhering to the immediate submission protocol."""
        return self.submit(challenge_id=challenge_id, flag=flag, strict=strict)

    def submit(self, challenge_id: Any, flag: str, strict: bool = False) -> SubmitResult:

        flag = flag.strip()
        chall_name = f"ID: {challenge_id}"
        
        # Check runtime state
        st = self.runtime_manager.read_challenge_state(self.event_id, challenge_id)
        if st and st.get("name"):
            chall_name = f"{st.get('name')} (ID: {challenge_id})"

        console.print(f"[bold cyan]🚩 Processing flag submission for [yellow]{chall_name}[/yellow]...[/bold cyan]")

        # 1. Validate format
        is_valid = self.validate_format(flag)
        if not is_valid:
            if strict:
                console.print(f"[bold red]❌ SUBMISSION REJECTED: Flag does not match format '{self.flag_format}' or is a placeholder![/bold red]")
                return SubmitResult(
                    verdict="invalid_format",
                    message=f"Flag does not match format '{self.flag_format}'.",
                    challenge_id=challenge_id,
                    challenge_name=chall_name,
                    flag=flag
                )
            else:
                console.print(f"[bold yellow]⚠️ Warning: Flag does not match format '{self.flag_format}'![/bold yellow]")

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
        raw_res = self.platform.submit_flag(challenge_id, flag)
        if isinstance(raw_res, dict):
            v_val = raw_res.get("status", raw_res.get("verdict", "unknown"))
            result = SubmitResult(
                verdict=v_val,
                message=raw_res.get("message", ""),
                challenge_id=challenge_id,
                challenge_name=chall_name,
                flag=flag,
            )
        else:
            result = raw_res
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
                lambda d: {**d, "solved": True, "solved_by_me": True, "status": "solved"}
            )
            return result

        # 6. Failure handling
        self._display_manual_intervention_alert(chall_name, challenge_id, flag, result)
        self._log_failed_flag(challenge_id, chall_name, flag, result.message)
        return result

    def auto_scan_and_submit(self) -> List[SubmitResult]:
        """Scan runtime challenges for new work/flag.txt files."""
        console.print("[cyan]🔍 Scanning for new flags in runtime...[/cyan]")
        results: List[SubmitResult] = []

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
        log_file = epath / ".failed_flags.jsonl"
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "challenge_id": str(cid),
            "challenge_name": cname,
            "flag_hash": self._hash_flag(cid, flag),
            "flag_masked": self._mask_flag(flag),
            "reason": reason,
        }
        try:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
            self._ensure_secure_file(log_file)
        except Exception:
            pass
