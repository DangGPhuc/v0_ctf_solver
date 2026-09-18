import shutil
import subprocess
from rich.console import Console

console = Console()

class BrowserBridge:
    @staticmethod
    def copy_to_clipboard(text: str) -> bool:
        """Copy text to X11 or Wayland clipboard."""
        for cmd in [["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"], ["wl-copy"]]:
            if shutil.which(cmd[0]):
                try:
                    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
                    proc.communicate(input=text.encode("utf-8"))
                    return proc.returncode == 0
                except Exception:
                    pass
        return False

    @staticmethod
    def open_firefox(url: str = "https://chatgpt.com/"):
        """Open URL in Firefox."""
        if shutil.which("firefox"):
            try:
                subprocess.Popen(["firefox", "--new-tab", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                console.print(f"[bold green]✔ Đã mở tab {url} trên Firefox![/bold green]")
                return True
            except Exception as e:
                console.print(f"[yellow]⚠️ Không thể mở Firefox: {e}[/yellow]")
        return False

    @staticmethod
    def consult_oracle_bridge(prompt: str) -> str | None:
        """
        Attempts communication with Oracle CLI bridge if installed.
        Returns response string if successful, or None.
        """
        if shutil.which("oracle-bridge"):
            try:
                res = subprocess.run(["oracle-bridge", "ask"], input=prompt, capture_output=True, text=True, timeout=120)
                if res.returncode == 0 and res.stdout.strip():
                    return res.stdout.strip()
            except Exception:
                pass
        return None
