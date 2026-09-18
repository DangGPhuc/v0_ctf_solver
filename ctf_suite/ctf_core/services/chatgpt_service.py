import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional
from rich.console import Console
from rich.panel import Panel

from ..models import Challenge
from ..workspace.repo import WorkspaceRepo

console = Console()

class ChatGPTService:
    def __init__(self, workspace_dir: Path, reverse_skill_dir: Optional[Path] = None):
        self.workspace_dir = Path(workspace_dir).resolve()
        self.reverse_skill_dir = (
            Path(reverse_skill_dir).resolve()
            if reverse_skill_dir
            else self.workspace_dir.parent / "reverse-skill"
        )
        self.repo = WorkspaceRepo(self.workspace_dir)

    def prepare_triage_prompt(self, challenge_id: Any) -> Dict[str, Any]:
        """
        Tự động bóc tách thông tin challenge (đề bài, hints, file đính kèm, strings, checksec)
        và sinh ra một Prompt hoàn chỉnh cho ChatGPT Web để nhận hướng giải quyết.
        """
        chall_dir = self.repo.find_challenge_dir(challenge_id)
        if not chall_dir:
            raise ValueError(f"Không tìm thấy thư mục cho Challenge ID: {challenge_id}")

        meta = self.repo.read_challenge_metadata(chall_dir) or {}
        name = meta.get("name", f"Challenge_{challenge_id}")
        category = meta.get("category", "Misc")
        points = meta.get("points", 0)
        desc = meta.get("description", "")
        conn = meta.get("connection_info", "")
        hints = meta.get("hints", [])

        # 1. Thu thập thông tin triage file đính kèm
        attachments_dir = chall_dir / "challenge"
        file_triage_info = []
        if attachments_dir.is_dir():
            for fpath in attachments_dir.iterdir():
                if fpath.name in ["README.md", "metadata.json", "flag.txt"] or fpath.is_dir():
                    continue
                file_info = self._analyze_attachment(fpath)
                file_triage_info.append(file_info)

        triage_text = "\n\n".join(file_triage_info) if file_triage_info else "*Không có tệp đính kèm.*"

        hints_text = ""
        if hints:
            hints_text = "\n".join([f"- Hint: {h.get('content', str(h)) if isinstance(h, dict) else str(h)}" for h in hints])
        else:
            hints_text = "*Không có hint.*"

        # 2. Lấy ngữ cảnh bổ sung từ repo Always_is_ (reverse-skill)
        repo_context = self._get_repo_context(category, file_triage_info)

        # 3. Xây dựng prompt chuẩn hóa cao cấp gắn kèm kho tri thức Always_is_
        prompt = f"""Bạn là cố vấn chiến thuật giải đề CTF cao cấp cho Đội Always_is_.
Toàn bộ quy trình giải bài tuân thủ nghiêm ngặt cẩm nang tác chiến (Playbooks, Rules & Templates) của Đội.
Hãy phân tích challenge dưới đây, xác định bản chất lỗ hổng và xuất ra chiến lược khai thác cùng mã nguồn solver Python hoàn chỉnh.

### THÔNG TIN BÀI TẬP:
- **Tên bài**: {name} (ID: {challenge_id})
- **Category**: {category}
- **Điểm số**: {points} pts
- **Thông tin kết nối (Service/URL)**: {conn or "Chưa có"}

### ĐỀ BÀI (Description):
{desc or "Không có mô tả."}

### GỢI Ý (Hints):
{hints_text}

### PHÂN TÍCH TỆP ĐÍNH KÈM & CHỮ KÝ (Static Triage):
{triage_text}

---
### QUY TẮC TÁC CHIẾN CỦA ĐỘI ALWAYS_IS_ (Operational Directives):
1. **Evidence-Based & Exploit-First**: Không giải thích dài dòng hay lý thuyết suông. Tập trung trực tiếp vào điểm yếu, vector tấn công và mã khai thác thực thi được ngay.
2. **3-Strike Rule**: Đưa ra 1 vector chính và ít nhất 1 vector dự phòng (alternative vector) nếu vector chính bị chặn bởi WAF/sandbox/mitigation.
3. **Chuẩn mã nguồn Solver**: Solver phải viết bằng Python 3 hoàn chỉnh, có xử lý kết nối (local/remote), tự động phân tích payload, và in ra Flag đúng định dạng (ví dụ: `NNS{{...}}` hoặc `FLAG{{...}}`).

{repo_context}

---
### YÊU CẦU ĐẦU RA CHO BẠN:
1. **Root Cause Analysis (Phân tích nguyên nhân gốc)**: Lỗ hổng hoặc cơ chế kiểm tra cờ nằm ở đâu trong mã/file?
2. **Attack Vector & Primtives**: Các bước kỹ thuật cụ thể để bẻ khóa bài tập.
3. **Mã nguồn Solver chuẩn (Full Python Script)**:
   - Sẵn sàng chạy ngay để thu hoạch Flag.
   - Bắt và in cờ ra màn hình dạng `print(f"[+] FLAG: {{flag}}")`.
"""
        # 4. Lưu prompt vào script/chatgpt_prompt.md
        prompt_file = chall_dir / "script" / "chatgpt_prompt.md"
        prompt_file.parent.mkdir(parents=True, exist_ok=True)
        prompt_file.write_text(prompt, encoding="utf-8")

        # 4. Sao chép bài tập và prompt sang reverse-skill/work/
        rs_work_dir = self._sync_to_reverse_skill(chall_dir, meta, prompt)

        return {
            "challenge_id": challenge_id,
            "challenge_name": name,
            "prompt_file": prompt_file,
            "prompt_text": prompt,
            "reverse_skill_dir": rs_work_dir
        }

    def _get_repo_context(self, category: str, file_triage_info: List[str]) -> str:
        """Trích xuất playbook và solver template tương ứng từ kho Always_is_ (reverse-skill)."""
        if not self.reverse_skill_dir or not self.reverse_skill_dir.is_dir():
            return ""

        cat_clean = category.lower().strip()
        cat_map = {
            "pwn": "pwn",
            "rev": "rev",
            "reverse": "rev",
            "crypto": "crypto",
            "cryptography": "crypto",
            "web": "web",
            "blockchain": "web",
            "boot2root": "pwn",
            "forensics": "forensics",
            "misc": "misc"
        }
        mapped_cat = cat_map.get(cat_clean, "misc")

        sections = [f"### CẨM NANG & SOLVER MẪU TỪ REPO ALWAYS_IS_ (Category: {category.upper()}):"]

        # 1. Tra cứu solver template trong templates/
        tpl_name = f"solve_{mapped_cat}.py"
        if mapped_cat == "crypto":
            tpl_path = self.reverse_skill_dir / "templates" / "solve_crypto.sage"
            if not tpl_path.is_file():
                tpl_path = self.reverse_skill_dir / "templates" / "solve_crypto.py"
        else:
            tpl_path = self.reverse_skill_dir / "templates" / tpl_name

        if tpl_path.is_file():
            tpl_content = tpl_path.read_text(encoding="utf-8")
            # Giới hạn 50 dòng đầu của template mẫu để prompt không quá dài
            tpl_snippet = "\n".join(tpl_content.splitlines()[:50])
            sections.append(f"- **Solver Boilerplate khuyên dùng ({tpl_path.name})**:\n```python\n{tpl_snippet}\n```")

        # 2. Tra cứu playbook tương ứng trong skills/<category>/
        skills_cat_dir = self.reverse_skill_dir / "skills" / mapped_cat
        if skills_cat_dir.is_dir():
            playbooks = [p.name for p in skills_cat_dir.glob("*.md") if not p.name.startswith("_")]
            if playbooks:
                sections.append(f"- **Các Playbook sẵn có trong repo Always_is_**: {', '.join(playbooks)}")

        # 3. Tra cứu field-journal nếu có bài tương tự
        journal_dir = self.reverse_skill_dir / "skills" / "field-journal"
        if journal_dir.is_dir():
            recent_journals = [j.name for j in journal_dir.glob("*.md") if not j.name.startswith("_")][:3]
            if recent_journals:
                sections.append(f"- **Field-Journal kinh nghiệm gần đây**: {', '.join(recent_journals)}")

        return "\n\n".join(sections)

    def _analyze_attachment(self, fpath: Path) -> str:
        """Thực hiện trích xuất nhanh thông tin file: file command, checksec, strings."""
        details = [f"#### Tệp: `{fpath.name}` ({fpath.stat().st_size} bytes)"]
        
        # Chạy file command
        try:
            res_file = subprocess.run(["file", "-b", str(fpath)], capture_output=True, text=True, timeout=5)
            details.append(f"- **Loại tệp**: `{res_file.stdout.strip()}`")
        except Exception:
            pass

        # Nếu là file ELF -> chạy checksec
        try:
            res_checksec = subprocess.run(["checksec", f"--file={fpath}"], capture_output=True, text=True, timeout=5)
            if res_checksec.returncode == 0:
                details.append(f"- **Checksec**:\n```text\n{res_checksec.stdout.strip()}\n```")
        except Exception:
            pass

        # Trích xuất strings hữu ích
        try:
            res_strings = subprocess.run(["strings", "-n", "7", str(fpath)], capture_output=True, text=True, timeout=5)
            lines = res_strings.stdout.splitlines()
            interesting = [
                line for line in lines
                if re.search(r'(flag|ctf|key|pass|admin|secret|system|bin/sh|eval|SELECT|INSERT|POST|GET)', line, re.IGNORECASE)
            ][:20]
            if interesting:
                details.append("- **Các chuỗi đáng ngờ (Strings)**:\n```text\n" + "\n".join(interesting) + "\n```")
        except Exception:
            pass

        return "\n".join(details)

    def prepare_deadlock_prompt(
        self,
        challenge_id: Any,
        progress: str,
        blocker: str,
        failed_attempts: str,
        error_trace: Optional[str] = None,
        code_snippet: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Tự động đóng gói bối cảnh bế tắc (Deadlock Escalation) thành Prompt chuyên sâu cho ChatGPT Web:
        - Đề bài, hints, thông tin kết nối và chữ ký tĩnh
        - Tiến độ hiện tại (những gì đã giải mã/phân tích thành công)
        - Điểm nghẽn cốt lõi (The Blocker)
        - Các hướng tiếp cận đã thử nhưng thất bại (Failed Attempts - yêu cầu ChatGPT TUYỆT ĐỐI KHÔNG lặp lại)
        - Error Trace / Log lỗi / Mã nguồn solver hiện tại (nếu có)
        Yêu cầu ChatGPT đưa ra góc nhìn toán học/thuật toán mới hoặc kỹ thuật bypass novel.
        """
        chall_dir = self.repo.find_challenge_dir(challenge_id)
        if not chall_dir:
            raise ValueError(f"Không tìm thấy thư mục cho Challenge ID: {challenge_id}")

        meta = self.repo.read_challenge_metadata(chall_dir) or {}
        name = meta.get("name", f"Challenge_{challenge_id}")
        category = meta.get("category", "Misc")
        points = meta.get("points", 0)
        desc = meta.get("description", "")
        conn = meta.get("connection_info", "")
        hints = meta.get("hints", [])

        hints_text = ""
        if hints:
            hints_text = "\n".join([f"- Hint: {h.get('content', str(h)) if isinstance(h, dict) else str(h)}" for h in hints])
        else:
            hints_text = "*Không có hint.*"

        trace_section = ""
        if error_trace:
            trace_section += f"\n### 6. NHẬT KÝ LỖI / EXECUTION TRACE:\n```text\n{error_trace.strip()}\n```\n"
        if code_snippet:
            trace_section += f"\n### 7. TRÍCH ĐOẠN CODE / PSEUDOCODE LIÊN QUAN:\n```python\n{code_snippet.strip()}\n```\n"

        prompt = f"""Bạn là một chuyên gia giải đề CTF (Competitive Capture The Flag) cao cấp đang hỗ trợ đồng đội giải quyết một bài tập gặp BẾ TẮC NGHIÊM TRỌNG (Deadlock Escalation).

Chúng tôi đã tiến hành khai thác và giải mã nhưng đã thất bại ở các hướng tiếp cận ban đầu. Hãy phân tích kỹ điểm nghẽn dưới đây và ĐỀ XUẤT HƯỚNG ĐI HOÀN TOÀN MỚI (Alternative Attack Vector / Mathematical Reduction / Out-of-the-box Bypass), TUYỆT ĐỐI KHÔNG lặp lại các hướng đã thất bại.

### 1. THÔNG TIN BÀI TẬP:
- **Tên bài**: {name} (ID: {challenge_id})
- **Category**: {category}
- **Điểm số**: {points} pts
- **Thông tin kết nối (Service/URL)**: {conn or "Chưa có"}

### 2. ĐỀ BÀI (Description) & GỢI Ý (Hints):
{desc or "Không có mô tả."}
{hints_text}

### 3. TIẾN ĐỘ ĐÃ ĐẠT ĐƯỢC (Current Progress):
{progress or "Đã tải file và phân tích tĩnh cơ bản."}

### 4. ĐIỂM NGHẼN CỐT LÕI (The Blocker):
{blocker}

### 5. CÁC HƯỚNG TIẾP CẬN ĐÃ THỬ NHƯNG THẤT BẠI (Failed Attempts - DO NOT REPEAT):
{failed_attempts}
{trace_section}
---
### YÊU CẦU ĐẶC BIỆT CHO BẠN:
1. **Phân tích nguyên nhân thất bại**: Tại sao các hướng tiếp cận trên lại không hiệu quả (do mô hình toán chưa tối ưu, thiếu primitive, sai offset, hay cơ chế filter ngầm)?
2. **Đề xuất ít nhất 2 hướng tiếp cận thay thế (Alternative Angles)**:
   - Hướng A: Tiếp cận từ góc độ toán học rút gọn hoặc tối ưu không gian mẫu (nếu là Crypto/Rev/Z3/PRNG).
   - Hướng B: Kỹ thuật bypass, cấu trúc dữ liệu thay thế hoặc primitive novel (nếu là Pwn/Web/Misc).
3. **Mã nguồn Solver / PoC thay thế hoàn chỉnh (Python)**:
   - Viết mã nguồn khắc phục trực tiếp điểm nghẽn nêu trên.
   - Có hàm trích xuất cờ theo định dạng chuẩn `FLAG{{...}}`.
"""
        # Lưu vào script/chatgpt_deadlock_prompt.md
        deadlock_file = chall_dir / "script" / "chatgpt_deadlock_prompt.md"
        deadlock_file.parent.mkdir(parents=True, exist_ok=True)
        deadlock_file.write_text(prompt, encoding="utf-8")

        # Cập nhật metadata
        meta.setdefault("deadlock_history", []).append({
            "blocker": blocker,
            "failed_attempts": failed_attempts,
            "progress": progress
        })
        self.repo.write_challenge_metadata(chall_dir, meta)

        # Sync sang reverse-skill
        rs_work_dir = self._sync_to_reverse_skill(chall_dir, meta, prompt, prompt_name="chatgpt_deadlock_prompt.md")

        return {
            "challenge_id": challenge_id,
            "challenge_name": name,
            "prompt_file": deadlock_file,
            "prompt_text": prompt,
            "reverse_skill_dir": rs_work_dir
        }

    def _sync_to_reverse_skill(
        self,
        chall_dir: Path,
        meta: Dict[str, Any],
        prompt: str,
        prompt_name: str = "chatgpt_prompt.md"
    ) -> Optional[Path]:
        """Đồng bộ bài tập và prompt sang thư mục reverse-skill/work/ để áp dụng playbooks."""
        if not self.reverse_skill_dir or not self.reverse_skill_dir.is_dir():
            return None

        cat = meta.get("category", "misc").lower()
        name = meta.get("name", "chall")
        safe_name = re.sub(r'[^a-zA-Z0-9_\-]+', '_', name)
        
        dest_work = self.reverse_skill_dir / "work" / cat / safe_name
        dest_work.mkdir(parents=True, exist_ok=True)

        # Ghi prompt vào reverse-skill (nếu có yêu cầu đồng bộ prompt)
        (dest_work / prompt_name).write_text(prompt, encoding="utf-8")
        return dest_work

    def send_to_firefox_chatgpt(self, prompt_text: str) -> bool:
        """
        Tự động đẩy prompt lên clipboard và mở Firefox đến https://chatgpt.com/.
        Người dùng chỉ cần ấn Ctrl+V trên Firefox để nhận phân tích!
        """
        # 1. Đưa prompt vào clipboard qua xclip
        copied = False
        try:
            proc = subprocess.Popen(["xclip", "-selection", "clipboard"], stdin=subprocess.PIPE)
            proc.communicate(input=prompt_text.encode("utf-8"))
            if proc.returncode == 0:
                copied = True
        except Exception:
            pass

        # 2. Mở tab mới trên Firefox tới https://chatgpt.com/
        opened = False
        try:
            subprocess.Popen(["firefox", "-new-tab", "https://chatgpt.com/"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            opened = True
        except Exception as e:
            console.print(f"[yellow]⚠️ Không thể tự mở Firefox: {e}[/yellow]")

        if copied:
            console.print("[bold green]✔ Đã tự động copy Prompt phân tích challenge vào Clipboard![/bold green]")
        if opened:
            console.print("[bold cyan]✔ Đã mở tab https://chatgpt.com/ trên Firefox. Bạn chỉ cần ấn Ctrl+V và Enter![/bold cyan]")
            
        return copied and opened

    def save_chatgpt_guidance(self, challenge_id: Any, guidance_text: str):
        """Lưu kết quả phản hồi của ChatGPT vào challenge workspace và reverse-skill."""
        chall_dir = self.repo.find_challenge_dir(challenge_id)
        if not chall_dir:
            return

        guidance_file = chall_dir / "script" / "chatgpt_guidance.md"
        guidance_file.write_text(guidance_text, encoding="utf-8")

        # Lưu đồng thời vào reverse-skill/work/...
        meta = self.repo.read_challenge_metadata(chall_dir) or {}
        cat = meta.get("category", "misc").lower()
        name = re.sub(r'[^a-zA-Z0-9_\-]+', '_', meta.get("name", "chall"))
        rs_dest = self.reverse_skill_dir / "work" / cat / name / "chatgpt_guidance.md"
        if rs_dest.parent.is_dir():
            rs_dest.write_text(guidance_text, encoding="utf-8")

        console.print(f"[green]✔ Đã lưu hướng dẫn của ChatGPT vào: [bold]{guidance_file.name}[/bold][/green]")

    def resolve_challenge_chatgpt(
        self,
        challenge_id: Any,
        status: str,  # "solved", "pending", "unsolved"
        reason: Optional[str] = None,  # "too_hard", "no_runtime", or custom text
        flag: Optional[str] = None,
        notes: Optional[str] = None,
        tried: Optional[str] = None  # Các hướng ChatGPT đã thử nhưng chưa ra
    ) -> bool:
        """
        Đánh dấu kết quả từ ChatGPT:
        - 'solved': ChatGPT đã giải ra cờ -> lưu flag, đánh dấu xong, để sang 1 bên.
        - 'pending': ChatGPT chưa giải được (quá khó hoặc không thực thi được) -> chuyển về danh sách để Anti-IDE & reverse-skill giải tiếp.
        """
        chall_dir = self.repo.find_challenge_dir(challenge_id)
        if not chall_dir:
            return False

        meta = self.repo.read_challenge_metadata(chall_dir) or {}
        cg_info = meta.get("chatgpt_triage", {})
        cg_info["status"] = status
        
        # Chuẩn hóa nhãn lý do
        reason_label = reason or "chưa rõ"
        if reason in ["no_runtime", "runtime", "exec"]:
            reason_label = "Không thực thi được trên web (Cần container/gdb/IDA local)"
        elif reason in ["too_hard", "hard", "stuck"]:
            reason_label = "Bài quá khó (Đã thử nhiều hướng nhưng chưa ra)"
        elif reason in ["blocked", "filter"]:
            reason_label = "Bộ lọc web từ chối xử lý"
            
        cg_info["reason"] = reason_label
        if tried:
            cg_info["tried_approaches"] = tried
        if flag:
            cg_info["flag"] = flag.strip()
            meta["flag"] = flag.strip()
        if notes:
            cg_info["notes"] = notes
        meta["chatgpt_triage"] = cg_info

        if status == "solved" and flag:
            meta["solved_by_me"] = True
            self.repo.mark_challenge_solved(challenge_id, flag.strip())

        # Ghi chú chi tiết vào script/chatgpt_guidance.md để Anti-IDE nắm ngữ cảnh
        if status != "solved":
            guidance_path = chall_dir / "script" / "chatgpt_guidance.md"
            lines = [
                f"# 🛑 ChatGPT Triage Status: PENDING / CHƯA GIẢI ĐƯỢC",
                f"- **Lý do**: `{reason_label}`",
            ]
            if tried:
                lines.append(f"- **Các hướng ChatGPT đã thử nhưng thất bại**:\n  > {tried}")
            if notes:
                lines.append(f"- **Ghi chú thêm**: {notes}")
            lines.extend([
                "",
                "### 🎯 Khuyến nghị cho Anti-IDE:",
                "- Không lặp lại các hướng đã thử thất bại ở trên.",
                "- Nếu thiếu runtime: Bật container (`./ctf instance start <ID>`) hoặc chạy gdb/IDA Pro MCP.",
                "- Nếu quá khó: Tham chiếu `reverse-skill/skills/MASTER-ROUTING.md` và ReAct protocol để đào sâu lỗ hổng ẩn.",
                ""
            ])
            guidance_path.parent.mkdir(parents=True, exist_ok=True)
            guidance_path.write_text("\n".join(lines), encoding="utf-8")

        self.repo.write_challenge_metadata(chall_dir, meta)

        # Cập nhật trong challenges.json
        def _mut(data: Dict[str, Any]) -> Dict[str, Any]:
            for c in data.get("challenges", []):
                if str(c.get("id")) == str(challenge_id):
                    c["chatgpt_status"] = status
                    c["chatgpt_reason"] = reason_label
                    if status == "solved" and flag:
                        c["solved_by_me"] = True
                        c["flag"] = flag.strip()
            return data
        self.repo.update_challenges(_mut)
        return True

    def get_triage_report(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Báo cáo phân loại challenge:
        - chatgpt_solved: Đã giải xong bởi ChatGPT (set aside)
        - needs_local: Chưa giải được, phân loại theo lý do (quá khó vs thiếu runtime)
        - untriaged: Chưa đưa lên ChatGPT
        """
        data = self.repo.read_challenges() or {}
        challenges = data.get("challenges", [])
        
        report: Dict[str, List[Dict[str, Any]]] = {
            "chatgpt_solved": [],
            "needs_local": [],
            "untriaged": []
        }

        for c in challenges:
            cid = c.get("id")
            chall_dir = self.repo.find_challenge_dir(cid)
            meta = self.repo.read_challenge_metadata(chall_dir) if chall_dir else {}
            cg = (meta or {}).get("chatgpt_triage", {})
            st = cg.get("status") or c.get("chatgpt_status")
            
            item = {
                "id": cid,
                "name": c.get("name"),
                "category": c.get("category"),
                "points": c.get("points"),
                "flag": cg.get("flag") or c.get("flag"),
                "reason": cg.get("reason") or c.get("chatgpt_reason") or "Chưa rõ lý do",
                "tried": cg.get("tried_approaches", ""),
                "notes": cg.get("notes", "")
            }

            if c.get("solved_by_me") or st == "solved":
                report["chatgpt_solved"].append(item)
            elif st in ["pending", "needs_local", "failed"]:
                report["needs_local"].append(item)
            else:
                report["untriaged"].append(item)

        return report


