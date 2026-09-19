import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional


class StaticTriage:
    """
    Controlled static triage engine for challenge files.
    Security guarantee:
      - Uses safe pure-Python inspection by default.
      - NEVER executes uncontrolled host subprocesses (such as host 'file', 'checksec', 'strings')
        directly on untrusted challenge artifacts.
    """

    @classmethod
    def detect_file_type_pure_python(cls, fpath: Path, header: bytes) -> str:
        """Determines file type using binary magic signatures and lightweight inspection."""
        if header.startswith(b"\x7fELF"):
            is_64 = header[4] == 2 if len(header) > 4 else True
            is_le = header[5] == 1 if len(header) > 5 else True
            bits = "64-bit" if is_64 else "32-bit"
            endian = "LSB" if is_le else "MSB"
            byteorder = "little" if is_le else "big"
            machine = int.from_bytes(header[18:20], byteorder=byteorder) if len(header) >= 20 else 0
            arch_map = {
                0x03: "Intel 80386",
                0x3E: "x86-64",
                0x28: "ARM",
                0xB7: "ARM aarch64",
                0x08: "MIPS",
                0x0A: "MIPS",
                0xF3: "RISC-V",
            }
            arch = arch_map.get(machine, f"machine 0x{machine:x}")
            e_type = int.from_bytes(header[16:18], byteorder=byteorder) if len(header) >= 18 else 0
            obj_type = "executable" if e_type == 2 else ("shared object" if e_type == 3 else "relocatable")
            return f"ELF {bits} {endian} {obj_type}, {arch}"

        if header.startswith(b"MZ"):
            return "PE32/PE64 executable (Windows)"

        if header.startswith(b"\x00asm"):
            return "WebAssembly (WASM) binary module"

        if header.startswith(b"\xd4\xc3\xb2\xa1") or header.startswith(b"\n\r\r\n"):
            return "pcap capture file"

        if header.startswith(b"PK\x03\x04"):
            return "Zip archive data"

        if header.startswith(b"\x1f\x8b"):
            return "gzip compressed data"

        if header.startswith(b"7z\xbc\xaf\x27\x1c"):
            return "7-zip archive data"

        if header.startswith(b"BZh"):
            return "bzip2 compressed data"

        if header.startswith(b"\x89PNG\r\n\x1a\n"):
            return "PNG image data"

        if header.startswith(b"\xff\xd8\xff"):
            return "JPEG image data"

        # Check if text
        try:
            sample_text = header.decode("utf-8")
            if sample_text.startswith("#!"):
                first_line = sample_text.splitlines()[0]
                return f"Script text executable, {first_line}"
            if "def " in sample_text or "import " in sample_text:
                return "Python script text"
            if "{" in sample_text and "}" in sample_text:
                return "JSON or C-like source text"
            return "ASCII text"
        except UnicodeDecodeError:
            return "data"

    @classmethod
    def extract_interesting_strings(cls, fpath: Path, max_bytes: int = 5 * 1024 * 1024) -> List[str]:
        """Extracts printable ASCII strings containing CTF-relevant keywords without spawning host 'strings'."""
        try:
            with open(fpath, "rb") as f:
                content = f.read(max_bytes)
            # Find printable ASCII sequences >= 6 chars
            raw_matches = re.findall(rb"[\x20-\x7e]{6,}", content)
            interesting = []
            keywords = ["flag", "ctf", "admin", "pass", "key", "/bin/sh", "system", "secret"]
            for b in raw_matches:
                try:
                    s = b.decode("ascii")
                    s_lower = s.lower()
                    if any(k in s_lower for k in keywords):
                        if s not in interesting:
                            interesting.append(s)
                    if len(interesting) >= 15:
                        break
                except Exception:
                    continue
            return interesting
        except Exception:
            return []

    @classmethod
    def analyze_file(cls, fpath: Path) -> str:
        """Run safe static triage on a file using pure Python."""
        fpath = Path(fpath)
        if not fpath.is_file():
            return f"**File**: `{fpath.name}` (Không tồn tại)"

        size = fpath.stat().st_size
        lines = [f"#### 📄 Tệp: `{fpath.name}` ({size:,} bytes)"]

        try:
            with open(fpath, "rb") as f:
                header = f.read(64)
        except Exception as e:
            lines.append(f"- **Lỗi đọc file**: `{e}`")
            return "\n".join(lines)

        # 1. Pure-Python file type signature
        file_type = cls.detect_file_type_pure_python(fpath, header)
        lines.append(f"- **Định dạng (File Type)**: `{file_type}`")

        # 2. Pure-Python mitigations for ELF
        if header.startswith(b"\x7fELF"):
            from .fingerprint import FingerprintEngine
            is_64 = header[4] == 2 if len(header) > 4 else True
            byteorder = "little" if (len(header) > 5 and header[5] == 1) else "big"
            protections: List[str] = []
            FingerprintEngine._inspect_elf_protections_pure_python(fpath, header, is_64, byteorder, protections)
            if protections:
                lines.append(f"- **Mitigations**: `{', '.join(protections)}`")

        # 3. Pure-Python interesting strings (no host 'strings' subprocess)
        if size < 20 * 1024 * 1024:
            interesting = cls.extract_interesting_strings(fpath)
            if interesting:
                lines.append(f"- **Chuỗi đáng chú ý (Interesting Strings)**:\n```text\n" + "\n".join(interesting[:10]) + "\n```")

        return "\n".join(lines)

    @staticmethod
    def triage_directory(dir_path: Path) -> List[str]:
        dir_path = Path(dir_path)
        results = []
        if not dir_path.is_dir():
            return results

        ignored_names = {"README.md", "metadata.json", "flag.txt"}
        ignored_suffixes = {".id0", ".id1", ".id2", ".nam", ".til", ".i64", ".idb"}
        for p in sorted(dir_path.iterdir()):
            if p.is_file() and not p.name.startswith(".") and p.name not in ignored_names and p.suffix not in ignored_suffixes:
                results.append(StaticTriage.analyze_file(p))
        return results
