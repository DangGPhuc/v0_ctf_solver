#!/usr/bin/env python3
"""
CTF Fast Automated Triage & Playbook Router Tool
Analyzes challenge files or URLs and suggests the optimal Category, Playbook, and Solver Template.
Usage:
  python3 toolchain/triage.py <target_file_or_url>
"""

import sys
import os
import subprocess
import shutil
import re

def run_cmd(cmd):
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        return res.stdout.strip()
    except Exception:
        return ""

def triage_target(target):
    print("================================================================")
    print(f"        CTF TRIAGE REPORT: {target}                           ")
    print("================================================================")

    if not os.path.exists(target) and not target.startswith("http"):
        print(f"[-] Target '{target}' not found!")
        return

    # 1. URL / Web Target
    if target.startswith("http://") or target.startswith("https://"):
        print("[+] Detected Target Type: WEB ENDPOINT")
        print("  - Suggested Category : WEB")
        print("  - Recommended Playbook: skills/web/sqli-injection.md / ssti-payloads.md")
        print("  - Solver Template     : templates/solve_web.py")
        return

    # 2. File Analysis
    file_info = run_cmd(["file", target])
    print(f"[+] File Signature: {file_info}")

    # Check for ELF / PE (PWN or REV)
    if "ELF" in file_info or "PE32" in file_info or "Mach-O" in file_info:
        print("\n[+] Binary Security Properties (checksec):")
        checksec_out = run_cmd(["checksec", "--file=" + target])
        if checksec_out:
            print("  " + "\n  ".join(checksec_out.split("\n")))

        # Check strings for anti-debug & indicators
        strings_out = run_cmd(["strings", "-n", "6", target])
        anti_debug = [w for w in ["ptrace", "alarm", "RDTSC", "SIGALRM", "IsDebuggerPresent"] if w in strings_out]
        crypto_hints = [w for w in ["AES", "RSA", "MD5", "SHA256", "Salsa20", "ChaCha20", "sbox"] if w in strings_out]

        if anti_debug:
            print(f"\n[!] Anti-Analysis Indicators Found: {', '.join(anti_debug)}")
        if crypto_hints:
            print(f"[!] Cryptographic Constants/Symbols Found: {', '.join(crypto_hints)}")

        print("\n[★] ROUTING RECOMMENDATION:")
        if "gets" in strings_out or "strcpy" in strings_out or "system" in strings_out or "malloc" in strings_out:
            print("  - Primary Category   : PWN")
            print("  - Recommended Playbook: skills/pwn/stack-pwn.md / skills/pwn/heap-pwn.md")
            print("  - Solver Template     : templates/solve_pwn.py")
        else:
            print("  - Primary Category   : REV")
            print("  - Recommended Playbook: skills/rev/z3-solver.md / skills/rev/ida-mcp-playbook.md")
            print("  - Solver Template     : templates/solve_rev.py")
        return

    # Check for PCAP / Network capture
    if "pcap" in file_info.lower() or "capture" in file_info.lower() or target.endswith((".pcap", ".pcapng")):
        print("\n[+] Network Packet Capture Detected:")
        tshark_summary = run_cmd(["tshark", "-r", target, "-q", "-z", "io,phs"])
        if tshark_summary:
            print("  " + "\n  ".join(tshark_summary.split("\n")[:15]))
        print("\n[★] ROUTING RECOMMENDATION:")
        print("  - Primary Category   : FORENSICS")
        print("  - Recommended Playbook: skills/forensics/pcap-analysis.md")
        return

    # Check for Images / Steganography
    if "PNG" in file_info or "JPEG" in file_info or "Bitmap" in file_info:
        print("\n[+] Image File Detected:")
        exif_out = run_cmd(["exiftool", target])
        if exif_out:
            print("  " + "\n  ".join(exif_out.split("\n")[:10]))
        print("\n[★] ROUTING RECOMMENDATION:")
        print("  - Primary Category   : FORENSICS (Stego)")
        print("  - Recommended Playbook: skills/forensics/stego-carving.md")
        return

    # Check for Python Scripts / PyJails
    if "Python script" in file_info or target.endswith(".py"):
        with open(target, "r", errors="ignore") as f:
            content = f.read()
        if "eval(" in content or "exec(" in content or "__builtins__" in content or "input(" in content:
            print("\n[★] ROUTING RECOMMENDATION: PyJail Sandbox Detected!")
            print("  - Primary Category   : MISC (PyJail)")
            print("  - Recommended Playbook: skills/misc/pyjail-escape.md")
            print("  - Solver Template     : templates/solve_misc.py")
            return

    # Check for Crypto / Math challenge text
    if target.endswith((".sage", ".py", ".txt")):
        print("\n[★] ROUTING RECOMMENDATION: Cryptanalysis / Math:")
        print("  - Primary Category   : CRYPTO")
        print("  - Recommended Playbook: skills/crypto/rsa-attacks.md / lattice-attacks.md")
        print("  - Solver Template     : templates/solve_crypto.sage")
        return

    print("\n[★] GENERAL RECOMMENDATION:")
    print("  - Consult: skills/MASTER-ROUTING.md for manual signature matching.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 toolchain/triage.py <target_file_or_url>")
        sys.exit(1)
    triage_target(sys.argv[1])
