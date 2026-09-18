import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from ctf_core.models import ChallengeFingerprint


class FingerprintEngine:
    """
    Automated Triage & Deep Fingerprint Engine for CTF Challenges.
    Extracts binary architecture, protections, frameworks, primitives, and suspicious patterns
    from challenge files, description, hints, and network connection strings.
    """

    CTF_VOCABULARY = {
        # Pwn & Stack/Heap primitives
        "rop", "overflow", "gadget", "syscall", "ret2libc", "ret2win", "ret2csu",
        "srop", "stack-pivot", "canary", "pie", "nx", "relro", "heap", "tcache",
        "fastbin", "unsorted-bin", "large-bin", "uaf", "double-free", "format-string",
        "printf", "shellcode", "seccomp", "kernel", "driver", "slab", "oob",
        # Crypto primitives
        "rsa", "ecc", "ecdsa", "lattice", "lwe", "lll", "babai", "hnp", "knapsack",
        "coppersmith", "wiener", "boneh-durfee", "discrete-log", "diffie-hellman",
        "aes", "cbc", "padding-oracle", "gcm", "nonce-reuse", "prng", "lcg", "mt19937",
        # Web primitives
        "sqli", "blind-sqli", "ssti", "jwt", "oauth", "prototype-pollution", "deserialization",
        "pickle", "php-object-injection", "ysoserial", "race-condition", "toctou", "type-juggling",
        "ssrf", "xss", "csrf", "path-traversal", "lfi", "rfi", "graphql", "nosql",
        # Reversing & Embedded
        "z3", "angr", "symbolic", "vm", "bytecode", "custom-vm", "deobfuscation",
        "ollvm", "cff", "anti-debug", "ptrace", "arm-cortex-m", "zephyr", "ble", "bluetooth",
        "firmware", "wasm", "il2cpp", "apk", "smali",
        # Forensics
        "pcap", "tshark", "usb-hid", "volatility", "memory-dump", "stego", "lsb", "spectrogram",
    }

    CATEGORY_CANONICAL_MAP = {
        "binary exploitation": "pwn", "pwnable": "pwn", "pwn": "pwn",
        "reverse engineering": "rev", "reversing": "rev", "reverse": "rev", "rev": "rev",
        "cryptography": "crypto", "crypto": "crypto",
        "web exploitation": "web", "web": "web",
        "forensics": "forensics", "dfir": "forensics",
        "miscellaneous": "misc", "misc": "misc",
        "hardware": "hardware", "iot": "hardware",
        "devsecops": "cloud", "devsecoops": "cloud", "cloud": "cloud",
        "blockchain": "blockchain", "web3": "blockchain",
        "ai": "ai", "llm": "ai",
    }

    @classmethod
    def extract(
        cls,
        meta: Dict[str, Any],
        chall_dir: Optional[Path] = None,
        active_hypothesis: Optional[str] = None,
    ) -> ChallengeFingerprint:
        raw_cat = (meta.get("category") or "misc").lower().strip()
        category = cls.CATEGORY_CANONICAL_MAP.get(raw_cat, raw_cat)
        tags = [t.lower().strip() for t in meta.get("tags", []) if t]

        file_types: List[str] = list(meta.get("file_types", []))
        architectures: List[str] = []
        frameworks: List[str] = []
        protections: List[str] = list(meta.get("protections", []))
        primitives: List[str] = []
        suspicious_patterns: List[str] = list(meta.get("keywords", []))
        runtime_signals: Dict[str, Any] = {}

        # 1. Scan filesystem artifacts in input/ and work/
        if chall_dir is not None:
            scan_dirs = [chall_dir / "input", chall_dir / "work"]
            for sdir in scan_dirs:
                if not sdir.is_dir():
                    continue
                for fpath in sorted(sdir.iterdir()):
                    if not fpath.is_file() or fpath.name.startswith("."):
                        continue
                    cls._fingerprint_file(
                        fpath,
                        file_types,
                        architectures,
                        frameworks,
                        protections,
                        suspicious_patterns,
                        runtime_signals,
                    )

        # 2. Text heuristics from Challenge name, description, hints, connection info
        text_corpus = [
            meta.get("name", ""),
            meta.get("description", ""),
            meta.get("connection_info", ""),
            active_hypothesis or "",
        ]
        for h in meta.get("hints", []):
            if isinstance(h, dict):
                text_corpus.append(h.get("content", ""))
            else:
                text_corpus.append(str(h))

        full_text = " ".join(filter(None, text_corpus)).lower()
        words = set(re.findall(r"[a-z0-9_\-]+", full_text))

        for w in words:
            if w in cls.CTF_VOCABULARY:
                if w not in suspicious_patterns:
                    suspicious_patterns.append(w)
                if w in ["rop", "heap", "sqli", "ssti", "jwt", "rsa", "lattice", "overflow", "format-string", "path-traversal"]:
                    if w not in primitives:
                        primitives.append(w)

        # Heuristic primitive matching
        if "buffer" in full_text and ("overflow" in full_text or "large input" in full_text):
            if "stack-overflow" not in primitives:
                primitives.append("stack-overflow")
        if "select" in full_text or "database" in full_text or "sql" in full_text:
            if "sqli" not in primitives:
                primitives.append("sqli")
        if "bluetooth" in full_text or "gatt" in full_text:
            if "ble" not in suspicious_patterns:
                suspicious_patterns.append("ble")
        if "nc " in full_text or "tcp" in full_text or meta.get("connection_info"):
            runtime_signals["remote_target"] = True

        # Deduplicate while preserving order
        return ChallengeFingerprint(
            category=category,
            tags=list(dict.fromkeys(tags)),
            file_types=list(dict.fromkeys(file_types)),
            architectures=list(dict.fromkeys(architectures)),
            frameworks=list(dict.fromkeys(frameworks)),
            protections=list(dict.fromkeys(protections)),
            primitives=list(dict.fromkeys(primitives)),
            suspicious_patterns=list(dict.fromkeys(suspicious_patterns)),
            runtime_signals=runtime_signals,
            confidence=0.85 if (file_types or primitives) else 0.5,
        )

    @classmethod
    def _fingerprint_file(
        cls,
        fpath: Path,
        file_types: List[str],
        architectures: List[str],
        frameworks: List[str],
        protections: List[str],
        suspicious_patterns: List[str],
        runtime_signals: Dict[str, Any],
    ):
        fname = fpath.name.lower()

        # By extension
        if fname.endswith((".py", ".pyc")):
            file_types.append("python")
        elif fname.endswith((".pcap", ".pcapng")):
            file_types.append("pcap")
        elif fname.endswith((".zip", ".tar", ".gz", ".7z", ".bz2")):
            file_types.append("archive")
        elif fname.endswith((".apk", ".dex")):
            file_types.append("apk")
            frameworks.append("android")
        elif fname.endswith((".sol",)):
            file_types.append("solidity")
            frameworks.append("evm")
        elif fname.endswith((".js", ".ts", ".mjs")):
            file_types.append("javascript")
            frameworks.append("node")
        elif fname.endswith((".php",)):
            file_types.append("php")
        elif fname.endswith((".hex", ".bin", ".elf")):
            file_types.append("binary")

        # Binary header inspection
        try:
            with open(fpath, "rb") as f:
                header = f.read(32)

            if header.startswith(b"\x7fELF"):
                file_types.append("elf")
                # 32 or 64-bit
                is_64 = header[4] == 2
                is_le = header[5] == 1
                runtime_signals["endianness"] = "little" if is_le else "big"
                machine = header[18] if len(header) > 18 else 0

                if machine == 0x3E:  # EM_X86_64
                    architectures.append("x86-64")
                elif machine == 0x03:  # EM_386
                    architectures.append("x86")
                elif machine == 0x28:  # EM_ARM
                    architectures.append("arm")
                elif machine == 0xB7:  # EM_AARCH64
                    architectures.append("aarch64")
                elif machine in [0x08, 0x0A]:  # EM_MIPS
                    architectures.append("mips")
                elif machine == 0xF3:  # EM_RISCV
                    architectures.append("riscv")

                # Run checksec if available
                if shutil.which("checksec"):
                    res = subprocess.run(["checksec", f"--file={fpath}"], capture_output=True, text=True, timeout=3)
                    cout = (res.stdout + res.stderr).lower()
                    if "no canary" in cout:
                        protections.append("no-canary")
                    elif "canary found" in cout:
                        protections.append("canary")
                    if "no pie" in cout:
                        protections.append("no-pie")
                    elif "pie enabled" in cout:
                        protections.append("pie")
                    if "nx disabled" in cout:
                        protections.append("no-nx")
                    elif "nx enabled" in cout:
                        protections.append("nx")
                    if "partial relro" in cout:
                        protections.append("partial-relro")
                    elif "full relro" in cout:
                        protections.append("full-relro")
                    elif "no relro" in cout:
                        protections.append("no-relro")

            elif header.startswith(b"MZ"):
                file_types.append("pe")
                architectures.append("windows")

            elif header.startswith(b"\x00asm"):
                file_types.append("wasm")
                architectures.append("webassembly")

            elif header.startswith(b"\xd4\xc3\xb2\xa1") or header.startswith(b"\n\r\r\n"):
                file_types.append("pcap")

            # Check for Zephyr OS or RTOS strings in firmware
            if fpath.stat().st_size < 10 * 1024 * 1024:
                with open(fpath, "rb") as f:
                    content_bytes = f.read(1024 * 1024)
                if b"Zephyr" in content_bytes or b"zephyr" in content_bytes:
                    frameworks.append("zephyr")
                    architectures.append("arm-cortex-m")
                if b"FreeRTOS" in content_bytes:
                    frameworks.append("freertos")
        except Exception:
            pass
