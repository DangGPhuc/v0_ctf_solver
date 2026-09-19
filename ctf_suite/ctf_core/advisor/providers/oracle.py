import re
import shutil
import subprocess
from typing import List, Optional
from rich.console import Console

from ...models import AdvisorResult
from ..guidance_parser import GuidanceParser
from .base import BaseAdvisorProvider

console = Console()


class OracleAdvisorProvider(BaseAdvisorProvider):
    """
    Subprocess provider communicating with ChatGPT Web via the Oracle CLI bridge.
    """

    def __init__(self, timeout: int = 120):
        self.timeout = timeout

    def _build_command(self, prompt: str, oracle_session: Optional[str] = None) -> Optional[List[str]]:
        oracle_bin = shutil.which("oracle")
        if oracle_bin:
            cmd = [oracle_bin, "--engine", "browser", "--browser-attach-running"]
            if oracle_session:
                cmd.extend(["--followup", oracle_session])
            cmd.extend(["-p", prompt])
            return cmd

        npx_bin = shutil.which("npx")
        if npx_bin:
            cmd = [npx_bin, "-y", "@steipete/oracle", "--engine", "browser", "--browser-attach-running"]
            if oracle_session:
                cmd.extend(["--followup", oracle_session])
            cmd.extend(["-p", prompt])
            return cmd

        return None

    def consult(
        self,
        prompt: str,
        oracle_session: Optional[str] = None,
        challenge_id: Optional[str] = None,
    ) -> AdvisorResult:
        cmd = self._build_command(prompt, oracle_session)
        if not cmd:
            return AdvisorResult(
                status="PROVIDER_UNAVAILABLE",
                provider="oracle",
                message="Neither 'oracle' nor 'npx' CLI executable was found on PATH.",
            )

        console.print("[cyan]🤖 Đang kết nối ChatGPT Web qua Oracle Browser Bridge...[/cyan]")
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            if res.returncode == 0 and res.stdout.strip():
                stdout_text = res.stdout.strip()
                guidance = GuidanceParser.parse(stdout_text)
                new_session = None
                m = re.search(r"session[:\s]+([a-zA-Z0-9_\-]+)", stdout_text, re.IGNORECASE)
                if m:
                    new_session = m.group(1)
                console.print("[bold green]✔ Đã nhận phản hồi chiến lược từ ChatGPT Web qua Oracle![/bold green]")
                return AdvisorResult(
                    status="READY",
                    guidance=guidance,
                    provider="chatgpt-web",
                    message="Oracle consultation succeeded.",
                    session_id=new_session or oracle_session,
                    raw_response=stdout_text,
                )
            else:
                err_msg = res.stderr.strip()[:200]
                console.print(f"[yellow]⚠️ Oracle trả về lỗi hoặc không có phản hồi: {err_msg}[/yellow]")
                return AdvisorResult(
                    status="PROVIDER_UNAVAILABLE",
                    provider="oracle",
                    message=f"Oracle command returned error: {err_msg}",
                )
        except Exception as e:
            console.print(f"[yellow]⚠️ Lỗi khi thực thi Oracle CLI: {e}[/yellow]")
            return AdvisorResult(
                status="PROVIDER_UNAVAILABLE",
                provider="oracle",
                message=f"Oracle execution exception: {e}",
            )
