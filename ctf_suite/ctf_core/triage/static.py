import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List

class StaticTriage:
    @staticmethod
    def analyze_file(fpath: Path) -> str:
        """Run static triage on a file using file, checksec, strings, and size checks."""
        fpath = Path(fpath)
        if not fpath.is_file():
            return f"**File**: `{fpath.name}` (Không tồn tại)"

        size = fpath.stat().st_size
        lines = [f"#### 📄 Tệp: `{fpath.name}` ({size:,} bytes)"]

        # 1. file command
        if shutil.which("file"):
            try:
                res = subprocess.run(["file", "-b", str(fpath)], capture_output=True, text=True, timeout=5)
                file_type = res.stdout.strip()
                lines.append(f"- **Định dạng (File Type)**: `{file_type}`")
            except Exception:
                pass

        # 2. checksec (for ELF)
        if shutil.which("checksec"):
            try:
                res = subprocess.run(["checksec", "--file=" + str(fpath)], capture_output=True, text=True, timeout=5)
                checksec_out = res.stdout.strip()
                if checksec_out:
                    clean_checksec = "\n".join([f"    {l.strip()}" for l in checksec_out.splitlines() if l.strip()])
                    lines.append(f"- **Mitigations (Checksec)**:\n```text\n{clean_checksec}\n```")
            except Exception:
                pass

        # 3. strings
        if shutil.which("strings") and size < 20 * 1024 * 1024:
            try:
                res = subprocess.run(["strings", "-a", "-n", "6", str(fpath)], capture_output=True, text=True, timeout=5)
                str_lines = res.stdout.splitlines()
                flag_hints = [s for s in str_lines if any(k in s.lower() for k in ["flag", "ctf", "admin", "pass", "key", "/bin/sh", "system"])]
                if flag_hints:
                    interesting = flag_hints[:10]
                    lines.append(f"- **Chuỗi đáng chú ý (Interesting Strings)**:\n```text\n" + "\n".join(interesting) + "\n```")
            except Exception:
                pass

        return "\n".join(lines)

    @staticmethod
    def triage_directory(dir_path: Path) -> List[str]:
        dir_path = Path(dir_path)
        results = []
        if not dir_path.is_dir():
            return results

        for p in sorted(dir_path.iterdir()):
            if p.is_file() and not p.name.startswith("."):
                results.append(StaticTriage.analyze_file(p))
        return results
