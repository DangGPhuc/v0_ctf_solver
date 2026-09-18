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

console = Console()

class SubmitService:
    def __init__(
        self,
        workspace_dir: Path,
        platform_url: str,
        session_cookie: Optional[str] = None,
        api_token: Optional[str] = None,
        flag_format: Optional[str] = None,
        platform_type: Optional[str] = None
    ):
        self.workspace_dir = Path(workspace_dir).resolve()
        self.flag_format = flag_format or r"^FLAG\{.+\}$"
        self.repo = WorkspaceRepo(self.workspace_dir)
        p_type = platform_type or detect_platform_type(platform_url, session_cookie)
        self.platform = create_platform(
            platform_name=p_type,
            url=platform_url,
            session_cookie=session_cookie,
            api_token=api_token
        )
        self.ledger_file = self.workspace_dir / ".submitted_flags.jsonl"
        self._ensure_secure_file(self.ledger_file)

    def _ensure_secure_file(self, file_path: Path):
        """Đảm bảo file tồn tại hoặc được phân quyền 0600."""
        if file_path.exists():
            try:
                os.chmod(file_path, 0o600)
            except Exception:
                pass

    def validate_format(self, flag: str) -> bool:
        """
        Kiểm tra chặt chẽ cờ:
        - Không chứa placeholder mẫu (FLAG{...}, ... , flag_here, text rác)
        - Phải khớp toàn bộ (fullmatch) regex định dạng giải đấu
        """
        if not flag or not isinstance(flag, str):
            return False
        flag = flag.strip()

        # 1. Chặn các placeholder hoặc text hướng dẫn
        placeholders = ["flag{...}", "null0rigin{...}", "flag_here", "insert_flag", "..."]
        lower_flag = flag.lower()
        if any(p in lower_flag for p in placeholders):
            return False

        # Chặn các chuỗi rác do agent ghi nhầm (ví dụ: 'I think flag is...', chuỗi có xuống dòng)
        if "\n" in flag or "\r" in flag or len(flag) < 5:
            return False

        # 2. Kiểm tra regex fullmatch
        try:
            return bool(re.fullmatch(self.flag_format, flag))
        except Exception:
            # Fallback nếu flag_format không hợp lệ: chấp nhận nếu có dạng {...}
            return "{" in flag and flag.endswith("}")

    def _get_flag_hash(self, challenge_id: Any, flag: str) -> str:
        data = f"{challenge_id}:{flag.strip()}".encode("utf-8")
        return hashlib.sha256(data).hexdigest()

    def has_been_submitted(self, challenge_id: Any, flag: str) -> Optional[str]:
        """
        Kiểm tra xem flag này đã từng được nộp cho challenge_id hay chưa.
        Trả về verdict trước đó nếu đã nộp và không phải lỗi mạng/ratelimit.
        """
        if not self.ledger_file.exists():
            return None

        target_hash = self._get_flag_hash(challenge_id, flag)
        try:
            for line in self.ledger_file.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                entry = json.loads(line)
                if entry.get("hash") == target_hash:
                    verdict = entry.get("verdict")
                    # Nếu lần trước bị ratelimited hoặc error thì cho phép nộp lại
                    if verdict not in ["ratelimited", "error"]:
                        return verdict
        except Exception:
            pass
        return None

    def _record_submission(self, challenge_id: Any, flag: str, result: SubmitResult):
        """Ghi nhận vào sổ cái submitted_flags.jsonl với quyền bảo mật 0600."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "challenge_id": str(challenge_id),
            "flag": flag.strip(),
            "hash": self._get_flag_hash(challenge_id, flag),
            "verdict": result.verdict,
            "message": result.message
        }
        try:
            with open(self.ledger_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            self._ensure_secure_file(self.ledger_file)
        except Exception:
            pass

    def submit(self, challenge_id: Any, flag: str, strict: bool = False) -> SubmitResult:
        """
        Nộp flag tức thì ('ctf_submit_right_away') với các tầng bảo vệ:
        - Strict validation: từ chối nộp ngay lập tức nếu sai format (chế độ auto)
        - Ledger Deduplication: không bao giờ nộp lại cờ đã submit
        """
        flag = flag.strip()
        chall_dir = self.repo.find_challenge_dir(challenge_id)
        chall_name = f"ID: {challenge_id}"
        if chall_dir:
            meta = self.repo.read_challenge_metadata(chall_dir) or {}
            chall_name = f"{meta.get('name', '')} (ID: {challenge_id})"

        console.print(f"[bold cyan]🚩 Đang xử lý nộp flag cho [yellow]{chall_name}[/yellow]...[/bold cyan]")

        # 1. Kiểm tra định dạng flag (Strict mode cho automation)
        is_valid = self.validate_format(flag)
        if not is_valid:
            if strict:
                console.print(f"[bold red]❌ TỪ CHỐI NỘP: Flag '{flag}' không khớp định dạng '{self.flag_format}' hoặc là placeholder rác![/bold red]")
                return SubmitResult(
                    verdict="invalid_format",
                    message=f"Flag không khớp định dạng chuẩn '{self.flag_format}'.",
                    challenge_id=challenge_id,
                    flag=flag
                )
            else:
                console.print(f"[bold yellow]⚠️ Cảnh báo: Flag '{flag}' không khớp định dạng '{self.flag_format}'![/bold yellow]")

        # 2. Kiểm tra sổ cái deduplication
        prev_verdict = self.has_been_submitted(challenge_id, flag)
        if prev_verdict:
            console.print(f"[dim]⚡ Bỏ qua: Flag '{flag}' đã từng được nộp trước đó với kết quả [{prev_verdict}].[/dim]")
            return SubmitResult(
                verdict=prev_verdict,
                message=f"Flag này đã từng được gửi đi trước đó (Kết quả: {prev_verdict}).",
                challenge_id=challenge_id,
                flag=flag
            )

        # 3. Gửi flag lên platform
        result = self.platform.submit_flag(challenge_id, flag)
        result.challenge_name = chall_name

        # 4. Ghi nhận vào sổ cái
        self._record_submission(challenge_id, flag, result)

        # 5. Phân nhánh kết quả
        if result.verdict == "correct":
            console.print(Panel(
                Text.assemble(
                    ("🎉 XIN CHÚC MÙNG! BẠN ĐÃ GIẢI THÀNH CÔNG!\n\n", "bold green"),
                    ("Challenge : ", "bold"), (f"{chall_name}\n", "cyan"),
                    ("Flag      : ", "bold"), (f"{flag}\n", "bold yellow"),
                    ("Thông báo : ", "bold"), (f"{result.message}\n", "green"),
                ),
                title="[bold green]✔ FLAG ACCEPTED[/bold green]",
                border_style="green",
                expand=False
            ))
            # Cập nhật local status
            self.repo.mark_challenge_solved(challenge_id, flag)
            return result

        elif result.verdict == "already_solved":
            console.print(f"[cyan]ℹ Challenge {chall_name} đã được giải trước đó trên hệ thống.[/cyan]")
            self.repo.mark_challenge_solved(challenge_id, flag)
            return result

        # 6. Khi nộp thất bại (Rate limit / Sai flag / Auth fail / Lỗi mạng)
        self._display_manual_intervention_alert(chall_name, challenge_id, flag, result)
        self._log_failed_flag(challenge_id, chall_name, flag, result.message)
        return result

    def auto_scan_and_submit(self) -> List[SubmitResult]:
        """
        Quét đệ quy các thư mục challenge trong workspace để tìm flag.txt mới tạo,
        nộp ngay lập tức với chế độ strict và deduplication an toàn.
        """
        console.print("[cyan]🔍 Đang quét workspace để tìm flag tự động...[/cyan]")
        results: List[SubmitResult] = []

        for cdir in self.repo.iter_challenge_dirs():
            meta = self.repo.read_challenge_metadata(cdir) or {}
            if meta.get("solved_by_me"):
                continue

            cid = meta.get("id")
            candidates = [
                cdir / "solver" / "flag.txt",
                cdir / "challenge" / "flag.txt",
                cdir / "flag.txt"
            ]
            found_flag: Optional[str] = None
            for p in candidates:
                if p.is_file():
                    content = p.read_text(encoding="utf-8").strip()
                    if content and self.validate_format(content):
                        found_flag = content
                        break

            if found_flag and cid is not None:
                console.print(f"[bold green]🎯 Tìm thấy flag hợp lệ cho {meta.get('name')}:[/bold green] {found_flag}")
                res = self.submit(cid, found_flag, strict=True)
                results.append(res)

        if not results:
            console.print("[dim]Không tìm thấy flag mới chưa nộp nào trong workspace.[/dim]")
        return results

    def _display_manual_intervention_alert(
        self,
        chall_name: str,
        challenge_id: Any,
        flag: str,
        result: SubmitResult
    ):
        alert_text = Text.assemble(
            ("⚠️ CẢNH BÁO: NỘP FLAG THẤT BẠI TRÊN NỀN TẢNG!\n\n", "bold red"),
            ("Challenge  : ", "bold"), (f"{chall_name}\n", "white"),
            ("Flag       : ", "bold"), (f"{flag}\n", "bold yellow"),
            ("Lý do      : ", "bold"), (f"[{result.verdict.upper()}] {result.message}\n\n", "red"),
            ("👉 HÃY COPY FLAG Ở TRÊN VÀ NỘP THỦ CÔNG QUA TRÌNH DUYỆT ĐỂ KHÔNG BỎ LỠ ĐIỂM!\n", "bold bright_yellow")
        )
        console.print(Panel(
            alert_text,
            title="[bold red]🚨 MANUAL INTERVENTION REQUIRED[/bold red]",
            border_style="red",
            expand=False
        ))

    def _log_failed_flag(self, cid: Any, cname: str, flag: str, reason: str):
        log_file = self.workspace_dir / ".failed_flags.log"
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"[{now}] Challenge: {cname} (ID: {cid}) | Flag: {flag} | Reason: {reason}\n")
        self._ensure_secure_file(log_file)
