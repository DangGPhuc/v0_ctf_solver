#!/usr/bin/env python3
"""
CTF Toolchain Bootstrap & Environment Diagnostic Tool
Checks, diagnoses, and installs required CTF tools and Python libraries.
Usage:
  python3 bootstrap.py --check
  python3 bootstrap.py --install
"""

import sys
import shutil
import subprocess
import argparse

REQUIRED_BINARIES = [
    ("gdb", "GDB Debugger (GDB/GEF/pwndbg)"),
    ("checksec", "Checksec binary security properties analyzer"),
    ("tshark", "Wireshark CLI for network packet analysis"),
    ("binwalk", "Firmware & file carving analysis tool"),
    ("exiftool", "Image and media metadata extractor"),
    ("strings", "Binary strings extractor"),
    ("ropper", "ROP gadget finder"),
    ("one_gadget", "Libc one-gadget RCE locator"),
    ("seccomp-tools", "Linux seccomp filter inspection tool"),
    ("zsteg", "PNG/BMP steganography analyzer"),
    ("sage", "SageMath mathematical computation suite")
]

REQUIRED_PYTHON_MODULES = [
    ("pwn", "pwntools", "Binary exploitation framework"),
    ("z3", "z3-solver", "Theorem prover & SMT solver"),
    ("angr", "angr", "Binary symbolic execution platform"),
    ("Crypto", "pycryptodome", "Cryptographic algorithms library"),
    ("randcrack", "randcrack", "MT19937 Mersenne Twister predictor"),
    ("httpx", "httpx", "High-performance async HTTP client"),
    ("requests", "requests", "HTTP library"),
    ("scapy", "scapy", "Packet manipulation tool"),
    ("gmpy2", "gmpy2", "High precision integer arithmetic"),
    ("sympy", "sympy", "Symbolic mathematics in Python")
]

def check_environment():
    print("================================================================")
    print("        CTF TOOLCHAIN ENVIRONMENT DIAGNOSTIC                   ")
    print("================================================================")

    print("\n[+] 1. Checking System Executables:")
    missing_binaries = []
    for binary, desc in REQUIRED_BINARIES:
        path = shutil.which(binary)
        if path:
            print(f"  [✓] {binary:<15} : FOUND ({path})")
        else:
            print(f"  [✗] {binary:<15} : MISSING ({desc})")
            missing_binaries.append(binary)

    print("\n[+] 2. Checking Python Modules:")
    missing_modules = []
    for mod_name, pkg_name, desc in REQUIRED_PYTHON_MODULES:
        try:
            __import__(mod_name)
            print(f"  [✓] {pkg_name:<15} : INSTALLED")
        except ImportError:
            print(f"  [✗] {pkg_name:<15} : MISSING ({desc})")
            missing_modules.append(pkg_name)

    print("\n================================================================")
    if not missing_binaries and not missing_modules:
        print("[🎉] STATUS: All core CTF tools & libraries are ready to battle!")
    else:
        print(f"[!] STATUS: {len(missing_binaries)} binary tools and {len(missing_modules)} python packages missing.")
        print("[*] Run `python3 toolchain/bootstrap.py --install` to install missing packages.")
    print("================================================================")
    return missing_binaries, missing_modules

def install_dependencies(missing_binaries, missing_modules):
    if missing_modules:
        print(f"\n[*] Installing missing Python packages: {' '.join(missing_modules)}")
        cmd = [sys.executable, "-m", "pip", "install", "--upgrade"] + missing_modules
        try:
            subprocess.run(cmd, check=True)
            print("[+] Python packages installed successfully.")
        except Exception as e:
            print(f"[-] Error installing python packages: {e}")

    if missing_binaries:
        print(f"\n[*] Missing system binaries: {', '.join(missing_binaries)}")
        print("[*] You can install them via apt:")
        print(f"    sudo apt update && sudo apt install -y {' '.join(missing_binaries)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CTF Toolchain Bootstrap")
    parser.add_argument("--check", action="store_true", help="Check dependencies status")
    parser.add_argument("--install", action="store_true", help="Install missing packages")
    args = parser.parse_args()

    missing_bin, missing_mod = check_environment()
    if args.install:
        install_dependencies(missing_bin, missing_mod)
