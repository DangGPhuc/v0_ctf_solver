import re
import unicodedata
from pathlib import Path
from typing import Any, Dict, List, Optional
from ..models import Challenge, CTFInfo

def sanitize_name(text: str, default: str = "chall") -> str:
    """Loại bỏ ký tự đặc biệt, chuẩn hóa tên folder an toàn."""
    if not text:
        return default
    text = unicodedata.normalize("NFKD", text)
    text = "".join(c for c in text if not unicodedata.combining(c))
    text = re.sub(r'[\s/\\:*?"<>|]+', '_', text.strip())
    text = re.sub(r'[_]+', '_', text).strip('_')
    return text or default

class WorkspaceBuilder:
    @staticmethod
    def create_challenge_workspace(
        workspace_root: Path,
        challenge: Challenge,
        downloaded_files: Optional[List[Path]] = None
    ) -> Path:
        """
        Khởi tạo cây thư mục 4 tầng chuẩn:
          <Category>/<Challenge_Name>/
          ├── challenge/       # README.md, metadata.json, attachments
          ├── script/          # Thư mục nháp cho Agent
          ├── solver/          # solve.py chính thức
          └── writeup/         # Ghi chép writeup
        """
        cat_clean = sanitize_name(challenge.category or "Misc", default="Misc")
        name_clean = sanitize_name(challenge.name, default=f"chall_{challenge.id}")
        
        chall_dir = workspace_root / cat_clean / name_clean
        challenge_dir = chall_dir / "challenge"
        script_dir = chall_dir / "script"
        solver_dir = chall_dir / "solver"
        writeup_dir = chall_dir / "writeup"

        for d in [challenge_dir, script_dir, solver_dir, writeup_dir]:
            d.mkdir(parents=True, exist_ok=True)

        # 1. Ghi challenge/README.md
        readme_path = challenge_dir / "README.md"
        readme_content = WorkspaceBuilder._render_readme(challenge)
        readme_path.write_text(readme_content, encoding="utf-8")

        # 2. Ghi challenge/metadata.json
        meta_path = challenge_dir / "metadata.json"
        meta_content = challenge.model_dump_json(indent=2)
        meta_path.write_text(meta_content, encoding="utf-8")

        # 3. Ghi solver/solve.py (chỉ sinh nếu chưa tồn tại)
        solve_path = solver_dir / "solve.py"
        if not solve_path.is_file():
            solve_content = WorkspaceBuilder._generate_solve_template(challenge)
            solve_path.write_text(solve_content, encoding="utf-8")

        # 4. Ghi writeup/README.md (chỉ sinh nếu chưa tồn tại)
        writeup_path = writeup_dir / "README.md"
        if not writeup_path.is_file():
            writeup_content = f"# Writeup: {challenge.name}\n\n- **Category**: `{challenge.category}`\n- **Points**: `{challenge.points}`\n\n## 1. Vulnerability Analysis\n\n## 2. Exploitation Steps\n\n## 3. Flag\n```\nFLAG{{...}}\n```\n"
            writeup_path.write_text(writeup_content, encoding="utf-8")

        # 5. Sao chép các tệp tải về vào challenge/
        if downloaded_files:
            for src_file in downloaded_files:
                if src_file and src_file.is_file():
                    dest = challenge_dir / src_file.name
                    if not dest.is_file():
                        try:
                            os.link(src_file, dest)
                        except Exception:
                            import shutil
                            shutil.copy2(src_file, dest)

        # 6. Đồng bộ sang reverse-skill/work/<category>/<name>
        rev_skill_root = workspace_root.parent / "reverse-skill" / "work"
        if rev_skill_root.is_dir():
            rev_target = rev_skill_root / cat_clean.lower() / name_clean
            try:
                rev_target.parent.mkdir(parents=True, exist_ok=True)
                if not rev_target.exists() and not rev_target.is_symlink():
                    rev_target.symlink_to(chall_dir, target_is_directory=True)
            except Exception:
                pass

        return chall_dir

    @staticmethod
    def _render_readme(challenge: Challenge) -> str:
        lines = [
            f"# {challenge.name}",
            "",
            "| Thuộc tính | Giá trị |",
            "| :--- | :--- |",
            f"| **ID** | `{challenge.id}` |",
            f"| **Category** | `{challenge.category}` |",
            f"| **Points** | `{challenge.points}` |",
        ]
        if challenge.author:
            lines.append(f"| **Author** | {challenge.author} |")
        if challenge.solves_count is not None:
            lines.append(f"| **Solves** | {challenge.solves_count} |")
        if challenge.tags:
            lines.append(f"| **Tags** | {', '.join([f'`{t}`' for t in challenge.tags])} |")
        
        lines.append("")
        if challenge.connection_info:
            lines.extend([
                "## 🔌 Connection / Target Service",
                "```bash",
                f"{challenge.connection_info}",
                "```",
                ""
            ])
            
        lines.extend([
            "## 📝 Description",
            "",
            challenge.description or "*No description provided.*",
            "",
        ])

        if challenge.hints:
            lines.append("## 💡 Hints")
            for idx, h in enumerate(challenge.hints, 1):
                if isinstance(h, dict):
                    hint_txt = h.get("content") or h.get("hint") or str(h)
                else:
                    hint_txt = str(h)
                lines.append(f"- **Hint {idx}**: {hint_txt}")
            lines.append("")

        if challenge.files:
            lines.append("## 📦 Attachments")
            for f in challenge.files:
                fname = f.get("name") or "file"
                furl = f.get("url") or "#"
                lines.append(f"- [{fname}]({furl})")
            lines.append("")

        lines.extend([
            "## 🚩 Solution Status",
            f"- [{'x' if challenge.solved_by_me else ' '}] Solved",
            ""
        ])
        return "\n".join(lines)

    @staticmethod
    def _generate_solve_template(challenge: Challenge) -> str:
        cat_lower = (challenge.category or "").lower()
        conn = challenge.connection_info or ""

        # Check for host/port
        host = "127.0.0.1"
        port = "1337"
        if conn:
            m_nc = re.search(r'(?:nc\s+)?([a-zA-Z0-9.\-]+)\s+([0-9]{2,5})', conn)
            if m_nc:
                host = m_nc.group(1)
                port = m_nc.group(2)

        if "pwn" in cat_lower or "rev" in cat_lower or ("nc " in conn or port != "1337"):
            return f'''#!/usr/bin/env python3
"""
Solution for: {challenge.name} ({challenge.category})
Auto-generated by Anti-IDE CTF Lifecycle Suite
"""
from pwn import *

HOST = "{host}"
PORT = {port}

context.log_level = "debug"
# context.arch = "amd64"
# context.terminal = ["tmux", "splitw", "-h"]

def solve():
    if args.REMOTE:
        r = remote(HOST, PORT)
    else:
        # r = process("./chall")
        r = remote(HOST, PORT)

    # TODO: Exploit logic here
    # r.sendlineafter(b"> ", b"payload")

    r.interactive()

if __name__ == "__main__":
    solve()
'''
        elif "web" in cat_lower or "http" in conn:
            target_url = conn if conn.startswith("http") else "http://127.0.0.1:8080"
            return f'''#!/usr/bin/env python3
"""
Solution for: {challenge.name} ({challenge.category})
Auto-generated by Anti-IDE CTF Lifecycle Suite
"""
import os
import requests
from dotenv import load_dotenv

load_dotenv()

TARGET_URL = "{target_url}"
SESSION_COOKIE = os.getenv("SESSION_COOKIE", "")
API_TOKEN = os.getenv("API_TOKEN", "")

session = requests.Session()
if SESSION_COOKIE:
    session.headers.update({{"Cookie": SESSION_COOKIE}})
if API_TOKEN:
    session.headers.update({{"Authorization": f"Bearer {{API_TOKEN}}"}})

def solve():
    print(f"[*] Attacking: {{TARGET_URL}}")
    resp = session.get(TARGET_URL)
    print(f"[*] Status: {{resp.status_code}}")

    # TODO: Exploit logic here

if __name__ == "__main__":
    solve()
'''
        elif "crypto" in cat_lower:
            return f'''#!/usr/bin/env python3
"""
Solution for: {challenge.name} ({challenge.category})
Auto-generated by Anti-IDE CTF Lifecycle Suite
"""
from Crypto.Util.number import *
import hashlib

def solve():
    # TODO: Crypto decapsulation / math recovery
    pass

if __name__ == "__main__":
    solve()
'''
        else:
            return f'''#!/usr/bin/env python3
"""
Solution for: {challenge.name} ({challenge.category})
Auto-generated by Anti-IDE CTF Lifecycle Suite
"""

def solve():
    print("[*] Solving {challenge.name}...")
    # TODO: Solver script logic

if __name__ == "__main__":
    solve()
'''

    @staticmethod
    def generate_summary(workspace_root: Path, ctf_info: CTFInfo) -> Path:
        summary_path = workspace_root / "SUMMARY.md"
        total_challs = len(ctf_info.challenges)
        solved_challs = sum(1 for c in ctf_info.challenges if c.solved_by_me)
        total_pts = sum(c.points for c in ctf_info.challenges)
        solved_pts = sum(c.points for c in ctf_info.challenges if c.solved_by_me)

        by_category: Dict[str, List[Challenge]] = {}
        for c in ctf_info.challenges:
            by_category.setdefault(c.category or "Misc", []).append(c)

        lines = [
            f"# {ctf_info.title} — Progress Summary",
            "",
            f"> Platform: **{ctf_info.platform.upper()}** · URL: {ctf_info.url}",
            f"> Tiến độ: **{solved_challs}/{total_challs} Solved** ({solved_pts}/{total_pts} Pts)",
            "",
            "## Danh mục bài tập",
            ""
        ]

        for cat, challs in sorted(by_category.items()):
            cat_solved = sum(1 for c in challs if c.solved_by_me)
            lines.append(f"### {cat} ({cat_solved}/{len(challs)} Solved)")
            lines.append("| ID | Tên bài | Điểm | Solves | Trạng thái | Đường dẫn |")
            lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
            for c in challs:
                st = "✅ Solved" if c.solved_by_me else "⏳ Todo"
                c_dir = f"{sanitize_name(c.category)}/{sanitize_name(c.name)}"
                lines.append(f"| {c.id} | {c.name} | {c.points} | {c.solves_count or 0} | {st} | [{c_dir}/]({c_dir}/) |")
            lines.append("")

        summary_path.write_text("\n".join(lines), encoding="utf-8")
        return summary_path
