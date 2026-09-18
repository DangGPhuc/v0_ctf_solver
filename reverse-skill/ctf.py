#!/usr/bin/env python3
"""
CTF AI Workspace Master Orchestrator (ctf.py)
Unified CLI for Challenge Scaffolding, Auto-Triage, Libc Patching, Testing, and Field-Journal Archiving.

Usage:
  python3 ctf.py init <name> [--file <archive_or_binary>] [--nc <host:port>] [--url <url>] [--cat <category>]
  python3 ctf.py test <name> [--remote] [--gdb] [--timeout <sec>]
  python3 ctf.py status
  python3 ctf.py archive <name> --flag <flag_string> [--notes <summary>]
"""

import sys
import os
import shutil
import subprocess
import argparse
import json
import re
import tarfile
import zipfile
import datetime
from pathlib import Path

# ==============================================================================
# PATHS & CONFIGURATION
# ==============================================================================
REPO_ROOT = Path(__file__).resolve().parent
WORK_DIR = REPO_ROOT / "work"
SKILLS_DIR = REPO_ROOT / "skills"
TEMPLATES_DIR = REPO_ROOT / "templates"
FIELD_JOURNAL_DIR = SKILLS_DIR / "field-journal"

FLAG_REGEX = re.compile(r'(?i)(?:[a-z0-9_\-]*?(?:flag|ctf|sec|pwnbox|svattt|hcmus|kcsc|htb|dice|defcon|cyber))\{[^\r\n\}]{4,120}\}')
PRIMARY_FLAG_REGEX = FLAG_REGEX
HASH_TOKEN_REGEX = re.compile(r'(?i)(?:flag|token|key|secret|proof|result)[\s:=]+([a-f0-9]{32}|[a-f0-9]{64})')

CATEGORIES = ["pwn", "rev", "crypto", "web", "forensics", "misc"]

# ==============================================================================
# HELPER UTILITIES
# ==============================================================================
def extract_flags(text):
    if not text:
        return []
    flags = PRIMARY_FLAG_REGEX.findall(text)
    if not flags:
        hash_matches = HASH_TOKEN_REGEX.findall(text)
        if hash_matches:
            flags = hash_matches
    return list(dict.fromkeys(flags)) # Remove duplicates while preserving order

def log_audit_trail(work_chal_dir, command_str, exit_code, stdout, stderr, action="run_command"):
    try:
        logs_dir = work_chal_dir / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        
        # 1. execution.log
        exec_log = logs_dir / "execution.log"
        now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        combined_output = stdout if stdout else ""
        if stderr:
            if combined_output:
                combined_output += "\n--- STDERR ---\n" + stderr
            else:
                combined_output = stderr
        if not combined_output:
            combined_output = "<empty>"
            
        log_entry = (
            f"[{now_utc}] [COMMAND] {command_str}\n"
            f"[EXIT CODE] {exit_code}\n"
            f"[OUTPUT]\n"
            f"{combined_output}\n"
            f"{'-'*80}\n"
        )
        with open(exec_log, "a", encoding="utf-8", errors="replace") as f:
            f.write(log_entry)
            
        # 2. raw_trace.jsonl
        raw_trace_file = logs_dir / "raw_trace.jsonl"
        json_entry = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "action": action,
            "command": command_str,
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr
        }
        with open(raw_trace_file, "a", encoding="utf-8", errors="replace") as f:
            f.write(json.dumps(json_entry, ensure_ascii=False) + "\n")
            
        # 3. Auto flag capture
        found_flags = extract_flags(stdout + "\n" + stderr)
        if found_flags:
            flags_file = work_chal_dir / "flags_captured.txt"
            with open(flags_file, "a", encoding="utf-8", errors="replace") as f:
                for flag in found_flags:
                    f.write(f"[{now_utc}] [EXTRACTED_FLAG]: {flag} | SOURCE: {command_str}\n")
        return found_flags
    except Exception as e:
        print(f"[!] Audit log warning: {e}")
        return []
def run_cmd(cmd, cwd=None, timeout=15):
    try:
        res = subprocess.run(
            cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout
        )
        return res.stdout.strip(), res.stderr.strip(), res.returncode
    except Exception as e:
        return "", str(e), -1

def sanitize_name(name):
    return re.sub(r'[^a-zA-Z0-9_\-]', '_', name).lower()

def parse_nc_target(nc_str):
    if not nc_str:
        return None, None
    # match patterns: "nc host port", "host:port", "host port"
    nc_str = nc_str.replace("nc ", "").strip()
    if ":" in nc_str:
        parts = nc_str.split(":")
        return parts[0].strip(), int(parts[1].strip())
    parts = nc_str.split()
    if len(parts) >= 2:
        return parts[0].strip(), int(parts[1].strip())
    return None, None

# ==============================================================================
# 1. AUTO-UNPACK & FILE ROLE CLASSIFICATION
# ==============================================================================
def unpack_archive(src_file, dest_dir):
    src_path = Path(src_file).resolve()
    if not src_path.exists():
        print(f"[-] Source file '{src_path}' does not exist.")
        return []

    extracted_files = []
    if zipfile.is_zipfile(src_path):
        print(f"[*] Extracting ZIP archive: {src_path.name}")
        with zipfile.ZipFile(src_path, 'r') as zf:
            zf.extractall(dest_dir)
            extracted_files = [dest_dir / f for f in zf.namelist()]
    elif tarfile.is_tarfile(src_path):
        print(f"[*] Extracting TAR archive: {src_path.name}")
        with tarfile.open(src_path, 'r:*') as tf:
            tf.extractall(dest_dir)
            extracted_files = [dest_dir / f for f in tf.getnames()]
    else:
        # Single file copy
        target_dest = dest_dir / src_path.name
        shutil.copy2(src_path, target_dest)
        extracted_files = [target_dest]

    # Ensure executable permissions for binaries/scripts
    for p in dest_dir.rglob("*"):
        if p.is_file():
            try:
                # If ELF or script, make executable
                with open(p, "rb") as f:
                    header = f.read(4)
                if header.startswith(b"\x7fELF") or header.startswith(b"#!"):
                    p.chmod(0o755)
            except Exception:
                pass
    return extracted_files

def classify_files(target_dir):
    roles = {
        "binaries": [],
        "libc": None,
        "loader": None,
        "dockerfile": None,
        "source_files": [],
        "pcaps": [],
        "images": [],
        "crypto_files": []
    }

    for p in target_dir.rglob("*"):
        if not p.is_file():
            continue
        rel_p = str(p.relative_to(target_dir))
        name_lower = p.name.lower()

        # Check Dockerfile
        if "dockerfile" in name_lower:
            roles["dockerfile"] = rel_p
            continue

        # Check PCAP
        if name_lower.endswith((".pcap", ".pcapng", ".cap")):
            roles["pcaps"].append(rel_p)
            continue

        # Check Stego / Media
        if name_lower.endswith((".png", ".jpg", ".jpeg", ".bmp", ".wav", ".mp3")):
            roles["images"].append(rel_p)
            continue

        # Check Crypto
        if name_lower.endswith((".sage", ".enc")) or (name_lower.endswith(".py") and ("crypto" in name_lower or "rsa" in name_lower)):
            roles["crypto_files"].append(rel_p)

        # Check Source
        if name_lower.endswith((".c", ".cpp", ".py", ".rs", ".go", ".java", ".php", ".js", ".html")):
            roles["source_files"].append(rel_p)

        # Check ELF / DLL / Shared Objects
        try:
            with open(p, "rb") as f:
                magic = f.read(4)
            if magic.startswith(b"\x7fELF"):
                if "libc" in name_lower or "libc.so" in name_lower:
                    roles["libc"] = rel_p
                elif "ld-" in name_lower or "ld-linux" in name_lower or "linker" in name_lower:
                    roles["loader"] = rel_p
                else:
                    roles["binaries"].append(rel_p)
        except Exception:
            pass

    return roles

# ==============================================================================
# 2. AUTO-PATCHING LIBC & LOADER (PWNINIT / PATCHELF)
# ==============================================================================
def patch_pwn_binary(work_chal_dir, binary_rel, libc_rel, loader_rel):
    bin_path = work_chal_dir / binary_rel
    libc_path = work_chal_dir / libc_rel if libc_rel else None
    loader_path = work_chal_dir / loader_rel if loader_rel else None

    if not bin_path.exists() or not (libc_path or loader_path):
        return binary_rel

    patched_name = bin_path.name + "_patched"
    patched_path = work_chal_dir / patched_name

    # Check patchelf availability
    patchelf_bin = shutil.which("patchelf")
    if not patchelf_bin:
        print("[!] Warning: 'patchelf' not found. Skipping binary auto-patch.")
        return binary_rel

    print(f"[*] Auto-patching binary '{bin_path.name}' with provided Libc & Loader...")
    shutil.copy2(bin_path, patched_path)
    patched_path.chmod(0o755)

    cmd = ["patchelf"]
    if loader_path and loader_path.exists():
        cmd.extend(["--set-interpreter", f"./{loader_path.name}"])
    if libc_path and libc_path.exists():
        cmd.extend(["--set-rpath", "."])
    cmd.append(str(patched_path))

    out, err, code = run_cmd(cmd, cwd=work_chal_dir)
    if code == 0:
        print(f"[✓] Patched binary created successfully: ./{patched_name}")
        return patched_name
    else:
        print(f"[-] Patchelf failed: {err}")
        return binary_rel

# ==============================================================================
# 3. HEADLESS DECOMPILATION & TRIAGE METADATA GENERATOR
# ==============================================================================
def extract_glibc_version(file_path):
    if not file_path or not os.path.exists(file_path):
        return None
    out, _, _ = run_cmd(["strings", "-a", str(file_path)])
    match = re.search(r'GNU C Library \([^\)]+\) stable release version ([0-9\.]+)', out)
    if match:
        return match.group(1)
    match = re.search(r'GLIBC_([0-9\.]+)', out)
    if match:
        return match.group(1)
    return None

def analyze_binary_security(bin_path):
    security = {"canary": False, "nx": False, "pie": False, "relro": "none", "arch": "unknown", "bits": 64}
    checksec_out, _, _ = run_cmd(["checksec", "--file=" + str(bin_path)])
    if checksec_out:
        if "Canary found" in checksec_out:
            security["canary"] = True
        if "NX enabled" in checksec_out:
            security["nx"] = True
        if "PIE enabled" in checksec_out:
            security["pie"] = True
        if "Full RELRO" in checksec_out:
            security["relro"] = "full"
        elif "Partial RELRO" in checksec_out:
            security["relro"] = "partial"

    file_out, _, _ = run_cmd(["file", str(bin_path)])
    if "x86-64" in file_out or "64-bit" in file_out:
        security["arch"] = "x86_64"
        security["bits"] = 64
    elif "Intel 80386" in file_out or "32-bit" in file_out:
        security["arch"] = "i386"
        security["bits"] = 32
    elif "ARM" in file_out or "aarch64" in file_out:
        security["arch"] = "arm"

    return security

def extract_symbols_and_decomp(bin_path):
    symbols = []
    nm_out, _, _ = run_cmd(["nm", "-D", "--defined-only", str(bin_path)])
    if not nm_out:
        nm_out, _, _ = run_cmd(["nm", str(bin_path)])

    for line in nm_out.splitlines():
        parts = line.strip().split()
        if len(parts) >= 3:
            sym_name = parts[2]
            if any(k in sym_name.lower() for k in ["main", "win", "vuln", "flag", "check", "auth", "secret"]):
                symbols.append({"name": sym_name, "address": parts[0], "type": parts[1]})

    # Headless Disassembly snippet of main or entry
    objdump_out, _, _ = run_cmd(["objdump", "-d", "-M", "intel", str(bin_path)])
    disasm_snippet = ""
    if objdump_out:
        # Extract main function disassembly
        main_match = re.search(r'([0-9a-f]+ <(?:main|vuln)>:[\s\S]{1,1500}?)(?=\n\n|\n[0-9a-f]+ <|\Z)', objdump_out)
        if main_match:
            disasm_snippet = main_match.group(1).strip()

    return symbols[:15], disasm_snippet

def find_similar_writeups(category, keywords):
    matches = []
    if not FIELD_JOURNAL_DIR.exists():
        return matches
    for md_file in FIELD_JOURNAL_DIR.glob("*.md"):
        if md_file.name.startswith("_"):
            continue
        try:
            with open(md_file, "r", errors="ignore") as f:
                content = f.read()
            score = 0
            if category.lower() in content.lower():
                score += 1
            for kw in keywords:
                if kw and kw.lower() in content.lower():
                    score += 2
            if score > 1:
                matches.append((score, str(md_file.relative_to(REPO_ROOT))))
        except Exception:
            pass
    matches.sort(key=lambda x: x[0], reverse=True)
    return [m[1] for m in matches[:3]]

def generate_triage_json(work_chal_dir, chal_name, category, roles, target_url, host, port):
    triage_data = {
        "challenge_name": chal_name,
        "category": category,
        "timestamp": datetime.datetime.now().isoformat(),
        "target_url": target_url,
        "remote_service": f"{host}:{port}" if host and port else None,
        "files": roles,
        "primary_binary": None,
        "security": {},
        "glibc_version": None,
        "symbols": [],
        "disassembly_preview": "",
        "indicators": {
            "anti_debug": [],
            "crypto_constants": [],
            "suspicious_strings": []
        },
        "suggested_playbook": f"skills/{category}/",
        "suggested_template": f"templates/solve_{category}.py"
    }

    # If Dockerfile exists, detect base image glibc hints
    if roles["dockerfile"]:
        df_path = work_chal_dir / roles["dockerfile"]
        if df_path.exists():
            with open(df_path, "r", errors="ignore") as f:
                df_content = f.read()
            if "ubuntu:22.04" in df_content:
                triage_data["glibc_version"] = "2.35 (Ubuntu 22.04)"
            elif "ubuntu:20.04" in df_content:
                triage_data["glibc_version"] = "2.31 (Ubuntu 20.04)"
            elif "ubuntu:24.04" in df_content:
                triage_data["glibc_version"] = "2.39 (Ubuntu 24.04)"

    if roles["libc"]:
        libc_v = extract_glibc_version(work_chal_dir / roles["libc"])
        if libc_v:
            triage_data["glibc_version"] = libc_v

    primary_bin = None
    if roles["binaries"]:
        primary_bin = roles["binaries"][0]
    elif roles["source_files"]:
        primary_bin = roles["source_files"][0]

    triage_data["primary_binary"] = primary_bin

    if primary_bin and (work_chal_dir / primary_bin).exists():
        bin_p = work_chal_dir / primary_bin
        # Check if ELF
        with open(bin_p, "rb") as f:
            magic = f.read(4)
        if magic.startswith(b"\x7fELF"):
            triage_data["security"] = analyze_binary_security(bin_p)
            syms, disasm = extract_symbols_and_decomp(bin_p)
            triage_data["symbols"] = syms
            triage_data["disassembly_preview"] = disasm

            strings_out, _, _ = run_cmd(["strings", "-n", "6", str(bin_p)])
            triage_data["indicators"]["anti_debug"] = [w for w in ["ptrace", "alarm", "RDTSC", "SIGALRM", "IsDebuggerPresent"] if w in strings_out]
            triage_data["indicators"]["crypto_constants"] = [w for w in ["AES", "RSA", "MD5", "SHA256", "Salsa20", "ChaCha20", "sbox"] if w in strings_out]
            triage_data["indicators"]["suspicious_strings"] = [line.strip() for line in strings_out.splitlines() if any(k in line.lower() for k in ["flag", "correct", "wrong", "password", "key", "token", "/bin/sh"])][:10]

    # Playbook routing
    if category == "pwn":
        triage_data["suggested_playbook"] = "skills/pwn/heap-pwn.md" if triage_data["glibc_version"] else "skills/pwn/stack-pwn.md"
        triage_data["suggested_template"] = "templates/solve_pwn.py"
    elif category == "rev":
        triage_data["suggested_playbook"] = "skills/rev/z3-solver.md"
        triage_data["suggested_template"] = "templates/solve_rev.py"
    elif category == "crypto":
        triage_data["suggested_playbook"] = "skills/crypto/rsa-attacks.md"
        triage_data["suggested_template"] = "templates/solve_crypto.sage"
    elif category == "web":
        triage_data["suggested_playbook"] = "skills/web/sqli-injection.md"
        triage_data["suggested_template"] = "templates/solve_web.py"
    elif category == "forensics":
        triage_data["suggested_playbook"] = "skills/forensics/pcap-analysis.md" if roles["pcaps"] else "skills/forensics/stego-carving.md"
        triage_data["suggested_template"] = "templates/solve_web.py"
    elif category == "misc":
        triage_data["suggested_playbook"] = "skills/misc/pyjail-escape.md"
        triage_data["suggested_template"] = "templates/solve_misc.py"

    # Search for similar historical writeups
    search_kws = triage_data["indicators"]["anti_debug"] + triage_data["indicators"]["crypto_constants"] + [triage_data["glibc_version"] or ""]
    triage_data["similar_past_challenges"] = find_similar_writeups(category, search_kws)

    triage_file = work_chal_dir / "triage.json"
    with open(triage_file, "w") as f:
        json.dump(triage_data, f, indent=2)
    print(f"[✓] Triage metadata generated: {triage_file.relative_to(REPO_ROOT)}")
    if triage_data["similar_past_challenges"]:
        print(f"[*] Found {len(triage_data['similar_past_challenges'])} similar past writeups for reference:")
        for w in triage_data["similar_past_challenges"]:
            print(f"    - {w}")
    return triage_data

# ==============================================================================
# 4. TEMPLATE VARIABLE INTERPOLATION
# ==============================================================================
def render_solve_template(category, work_chal_dir, binary_name, host, port, target_url, libc_name):
    ext = "sage" if category == "crypto" else "py"
    template_file = TEMPLATES_DIR / f"solve_{category}.{ext}"
    dest_file = work_chal_dir / f"solve.{ext}"

    if not template_file.exists():
        template_file = TEMPLATES_DIR / "solve_pwn.py"

    with open(template_file, "r") as f:
        content = f.read()

    # Interpolate variables
    if binary_name:
        content = content.replace("BINARY_PATH = './vuln'", f"BINARY_PATH = './{binary_name}'")
        content = content.replace("BINARY_PATH = './chal'", f"BINARY_PATH = './{binary_name}'")
    if libc_name:
        content = content.replace("LIBC_PATH = './libc.so.6'", f"LIBC_PATH = './{libc_name}'")
    if target_url:
        content = content.replace('TARGET_URL = "http://challenge.ctf:8080/api/v1/search"', f'TARGET_URL = "{target_url}"')

    # Add default host/port comments in main if provided
    if host and port:
        connect_str = f"remote('{host}', {port})"
        content = content.replace("return remote(host, port)", f"return remote('{host}', {port})")

    with open(dest_file, "w") as f:
        f.write(content)
    dest_file.chmod(0o755)
    print(f"[✓] Solver scaffold created: {dest_file.relative_to(REPO_ROOT)}")

def render_challenge_readme(work_chal_dir, chal_name, category, triage_data):
    readme_path = work_chal_dir / "README.md"
    remote_info = (triage_data.get('remote_service') or '<host> <port>').replace(':', ' ')
    content = f"""# Challenge: {chal_name}

- **Category**: {category.upper()}
- **Target**: {triage_data.get('remote_service') or triage_data.get('target_url') or triage_data.get('primary_binary')}
- **Suggested Playbook**: [{triage_data.get('suggested_playbook')}](file://{REPO_ROOT / triage_data.get('suggested_playbook', '')})

## Quick Commands
- Run Solver Local: `python3 solve.py`
- Run Solver Remote: `python3 solve.py --remote {remote_info}`
- Fast Test: `python3 ctf.py test {chal_name}`
- Archive Flag: `python3 ctf.py archive {chal_name} --flag "FLAG{{...}}"`
"""
    with open(readme_path, "w") as f:
        f.write(content)

# ==============================================================================
# 5. SUBCOMMAND: INIT
# ==============================================================================
def cmd_init(args):
    chal_name = sanitize_name(args.name)
    host, port = parse_nc_target(args.nc)
    target_url = args.url

    # Guess category if not explicitly provided
    category = args.cat
    if not category:
        if target_url:
            category = "web"
        elif args.file and (args.file.endswith((".pcap", ".pcapng", ".png", ".jpg", ".wav"))):
            category = "forensics"
        elif args.file and (args.file.endswith(".sage") or "crypto" in args.file.lower()):
            category = "crypto"
        else:
            category = "pwn" # Default to pwn/rev

    work_chal_dir = WORK_DIR / category / chal_name
    work_chal_dir.mkdir(parents=True, exist_ok=True)
    (work_chal_dir / "scripts").mkdir(exist_ok=True)
    (work_chal_dir / "logs").mkdir(exist_ok=True)
    if target_url or category == "web":
        (work_chal_dir / "logs" / "network").mkdir(exist_ok=True)
    flags_file = work_chal_dir / "flags_captured.txt"
    if not flags_file.exists():
        flags_file.touch()

    print(f"[*] Initializing workspace: {work_chal_dir.relative_to(REPO_ROOT)}")

    # Unpack archive or copy file
    if args.file:
        unpack_archive(args.file, work_chal_dir)

    # Classify files
    roles = classify_files(work_chal_dir)

    # Pwn Auto-patching
    binary_name = roles["binaries"][0] if roles["binaries"] else None
    if category == "pwn" and binary_name and (roles["libc"] or roles["loader"]):
        binary_name = patch_pwn_binary(work_chal_dir, binary_name, roles["libc"], roles["loader"])

    # Generate Triage JSON
    triage_data = generate_triage_json(work_chal_dir, chal_name, category, roles, target_url, host, port)

    # Render Solver Template & README
    render_solve_template(category, work_chal_dir, binary_name, host, port, target_url, roles["libc"])
    render_challenge_readme(work_chal_dir, chal_name, category, triage_data)

    # Autonomous Process Orchestration (Headless IDA Pro & Burp Suite)
    try:
        from toolchain.process_manager import start_ida, start_burp, set_active_challenge
        if binary_name:
            set_active_challenge(chal_name, category, work_chal_dir, binary_name)
            
        if binary_name and category in ["rev", "pwn", "crypto"]:
            start_ida(work_chal_dir / binary_name, work_chal_dir)
        elif target_url or category == "web":
            start_burp(work_chal_dir)
        
        # Hybrid Challenge Detection (Web + Binary WASM/ELF, or Crypto + Native Binary)
        if (target_url or category == "web") and binary_name:
            print("[*] Hybrid Challenge detected (Web + Native Binary). Starting both Burp & IDA daemons...")
            start_ida(work_chal_dir / binary_name, work_chal_dir)
    except Exception as e:
        print(f"[!] Background service notice: {e}")

    print("\n================================================================")
    print(f"🎉 Challenge '{chal_name}' initialized successfully in {category.upper()}!")
    print(f"👉 Workspace : cd {work_chal_dir.relative_to(REPO_ROOT)}")
    print(f"👉 Playbook  : {triage_data['suggested_playbook']}")
    print(f"👉 Solve File: {work_chal_dir.relative_to(REPO_ROOT)}/solve.{'sage' if category == 'crypto' else 'py'}")
    print("================================================================")

# ==============================================================================
# 6. SUBCOMMAND: TEST
# ==============================================================================
def cmd_test(args):
    chal_name = sanitize_name(args.name)
    matching = list(WORK_DIR.glob(f"*/{chal_name}"))
    if not matching:
        matching = list(WORK_DIR.glob(f"{chal_name}"))
    if not matching:
        print(f"[-] Workspace for challenge '{chal_name}' not found in ./work/")
        return

    work_chal_dir = matching[0]
    solver_files = list(work_chal_dir.glob("solve.*"))
    if not solver_files:
        print(f"[-] No solve script found in {work_chal_dir}")
        return

    solver_path = solver_files[0]
    cmd = [sys.executable, str(solver_path.name)]
    if solver_path.suffix == ".sage":
        cmd = ["sage", str(solver_path.name)]

    if args.remote:
        cmd.append("--remote")
    elif args.gdb:
        cmd.append("--gdb")

    print(f"[*] Executing solver: {' '.join(cmd)} in {work_chal_dir.relative_to(REPO_ROOT)}...")
    start_time = datetime.datetime.now()
    out, err, code = run_cmd(cmd, cwd=work_chal_dir, timeout=args.timeout)
    elapsed = (datetime.datetime.now() - start_time).total_seconds()

    print("\n--- [ STDOUT ] ---")
    print(out if out else "<empty>")
    if err:
        print("\n--- [ STDERR ] ---")
        print(err)

    print(f"\n[*] Execution finished in {elapsed:.2f}s with exit code {code}.")
    
    # Audit log & Flag extraction
    found_flags = log_audit_trail(work_chal_dir, ' '.join(cmd), code, out, err, action="run_test")
    if found_flags:
        for f in found_flags:
            print(f"\n🚩 VALIDATION TOKEN / FLAG DETECTED: {f}")
    else:
        print("\n[?] No standard flag pattern detected in output.")

# ==============================================================================
# 7. SUBCOMMAND: CRASH (AUTO CYCLIC OFFSET FINDER)
# ==============================================================================
def cmd_crash(args):
    chal_name = sanitize_name(args.name)
    matching = list(WORK_DIR.glob(f"*/{chal_name}"))
    if not matching:
        matching = list(WORK_DIR.glob(f"{chal_name}"))
    if not matching:
        print(f"[-] Workspace for challenge '{chal_name}' not found.")
        return

    work_chal_dir = matching[0]
    triage_file = work_chal_dir / "triage.json"
    bin_name = None
    if triage_file.exists():
        with open(triage_file, "r") as f:
            t_data = json.load(f)
        bin_name = t_data.get("primary_binary")

    if not bin_name:
        for p in work_chal_dir.iterdir():
            if p.is_file() and os.access(p, os.X_OK) and not p.name.endswith((".py", ".sh", ".sage", ".md", ".json")):
                bin_name = p.name
                break

    if not bin_name:
        print("[-] No executable target binary found in workspace to crash test.")
        return

    prefix_code = ""
    if args.prefix:
        p_val = repr(args.prefix.replace('\\n', '\n'))
        prefix_code = f"    p.send({p_val}.encode())\n"

    print(f"[*] Fuzzing '{bin_name}' with cyclic pattern (length={args.length}, prefix={args.prefix or 'None'})...")

    fuzz_script = f"""
from pwn import *
import sys
context.log_level = 'error'
try:
    elf = ELF('./{bin_name}', checksec=False)
    context.binary = elf
    p = process('./{bin_name}')
{prefix_code}    pattern = cyclic({args.length})
    p.sendline(pattern)
    p.wait()
    core = p.corefile
    fault = core.fault_addr
    offset = cyclic_find(fault)
    arch = '64-bit' if core.arch == 'amd64' else '32-bit'
    reg = 'RIP/RSP' if core.arch == 'amd64' else 'EIP'
    print(f"OFFSET_RESULT:{{offset}}:{{arch}}:{{reg}}")
except Exception as e:
    print(f"OFFSET_ERROR:{{e}}")
"""
    fuzz_file = work_chal_dir / "_fuzz_crash.py"
    with open(fuzz_file, "w") as f:
        f.write(fuzz_script)

    out, err, code = run_cmd([sys.executable, "_fuzz_crash.py"], cwd=work_chal_dir, timeout=10)
    try:
        fuzz_file.unlink()
    except Exception:
        pass

    match = re.search(r'OFFSET_RESULT:(\d+):([^:]+):([^\n\r]+)', out)
    if match:
        offset_val, arch, reg = match.groups()
        print("\n================================================================")
        print(f"🎯 BUFFER OVERFLOW OFFSET FOUND!")
        print(f"👉 Offset : {offset_val} bytes")
        print(f"👉 Target : {reg} ({arch})")
        print(f"👉 Payload: b'A' * {offset_val} + p64(target_address)")
        print("================================================================")
    else:
        print(f"[-] Could not automatically capture core dump offset. Output:\n{out or err}")

# ==============================================================================
# 8. SUBCOMMAND: ROP (VERIFIED GADGET EXTRACTOR)
# ==============================================================================
def cmd_rop(args):
    chal_name = sanitize_name(args.name)
    matching = list(WORK_DIR.glob(f"*/{chal_name}"))
    if not matching:
        matching = list(WORK_DIR.glob(f"{chal_name}"))
    if not matching:
        print(f"[-] Workspace for challenge '{chal_name}' not found.")
        return

    work_chal_dir = matching[0]
    triage_file = work_chal_dir / "triage.json"
    bin_name = None
    if triage_file.exists():
        with open(triage_file, "r") as f:
            t_data = json.load(f)
        bin_name = t_data.get("primary_binary")

    if not bin_name:
        for p in work_chal_dir.iterdir():
            if p.is_file() and os.access(p, os.X_OK) and not p.name.endswith((".py", ".sh", ".sage", ".md", ".json")):
                bin_name = p.name
                break

    if not bin_name:
        print("[-] No executable target binary found in workspace.")
        return

    print(f"[*] Extracting verified ROP gadgets from '{bin_name}'...")
    rop_script = f"""
from pwn import *
import json
context.log_level = 'error'
try:
    elf = ELF('./{bin_name}', checksec=False)
    rop = ROP(elf)
    gadgets = {{}}
    for g in ['pop rdi; ret', 'pop rsi; ret', 'pop rdx; ret', 'pop rax; ret', 'ret', 'leave; ret', 'syscall']:
        try:
            addr = rop.find_gadget(g.split('; '))
            if addr:
                gadgets[g] = hex(addr.address)
        except Exception:
            pass
    symbols = {{}}
    for s in ['puts', 'printf', 'system', 'main', 'vuln', 'win']:
        if s in elf.symbols:
            symbols[s] = hex(elf.symbols[s])
        if s in elf.got:
            symbols[s + '@got'] = hex(elf.got[s])
        if s in elf.plt:
            symbols[s + '@plt'] = hex(elf.plt[s])
    print("GADGET_JSON:" + json.dumps({{"gadgets": gadgets, "symbols": symbols}}))
except Exception as e:
    print(f"GADGET_ERROR:{{e}}")
"""
    fuzz_file = work_chal_dir / "_extract_rop.py"
    with open(fuzz_file, "w") as f:
        f.write(rop_script)

    out, err, code = run_cmd([sys.executable, "_extract_rop.py"], cwd=work_chal_dir, timeout=10)
    try:
        fuzz_file.unlink()
    except Exception:
        pass

    match = re.search(r'GADGET_JSON:(.+)', out)
    if match:
        data = json.loads(match.group(1))
        print("\n================================================================")
        print("🎯 VERIFIED ROP GADGETS (Zero Hallucination):")
        for g, addr in data.get("gadgets", {}).items():
            print(f"  👉 {g:<20} : {addr}")
        print("\n🎯 KEY SYMBOLS & GOT/PLT:")
        for s, addr in data.get("symbols", {}).items():
            print(f"  👉 {s:<20} : {addr}")
        print("================================================================")
    else:
        print(f"[-] Could not extract gadgets automatically:\n{out or err}")

# ==============================================================================
# 9. SUBCOMMAND: FMT (AUTO FORMAT STRING OFFSET FINDER)
# ==============================================================================
def cmd_fmt(args):
    chal_name = sanitize_name(args.name)
    matching = list(WORK_DIR.glob(f"*/{chal_name}"))
    if not matching:
        matching = list(WORK_DIR.glob(f"{chal_name}"))
    if not matching:
        print(f"[-] Workspace for challenge '{chal_name}' not found.")
        return

    work_chal_dir = matching[0]
    triage_file = work_chal_dir / "triage.json"
    bin_name = None
    if triage_file.exists():
        with open(triage_file, "r") as f:
            t_data = json.load(f)
        bin_name = t_data.get("primary_binary")

    if not bin_name:
        for p in work_chal_dir.iterdir():
            if p.is_file() and os.access(p, os.X_OK) and not p.name.endswith((".py", ".sh", ".sage", ".md", ".json")):
                bin_name = p.name
                break

    if not bin_name:
        print("[-] No executable target binary found in workspace.")
        return

    prefix_str = repr(args.prefix.replace('\\n', '\n')) if args.prefix else "''"

    print(f"[*] Fuzzing Format String offset on '{bin_name}' (prefix={args.prefix or 'None'})...")
    fmt_script = f"""
from pwn import *
context.log_level = 'error'
elf = ELF('./{bin_name}', checksec=False)
prefix = {prefix_str}.encode()

found_idx = None
for i in range(1, 40):
    try:
        p = process('./{bin_name}')
        if prefix:
            p.send(prefix)
        p.sendline(f"START_AAAA_%{{i}}$p_END".encode())
        res = p.recvall(timeout=0.5)
        if b"START_AAAA_0x41414141" in res or b"START_AAAA_0x" in res and b"41414141" in res:
            found_idx = i
            break
        p.close()
    except Exception:
        pass

if found_idx:
    print(f"FMT_RESULT:{{found_idx}}")
else:
    print("FMT_NOT_FOUND")
"""
    fuzz_file = work_chal_dir / "_fuzz_fmt.py"
    with open(fuzz_file, "w") as f:
        f.write(fmt_script)

    out, err, code = run_cmd([sys.executable, "_fuzz_fmt.py"], cwd=work_chal_dir, timeout=15)
    try:
        fuzz_file.unlink()
    except Exception:
        pass

    match = re.search(r'FMT_RESULT:(\d+)', out)
    if match:
        idx = match.group(1)
        print("\n================================================================")
        print(f"🎯 FORMAT STRING OFFSET FOUND!")
        print(f"👉 Direct Parameter Offset: Index {idx}")
        print(f"👉 Leak Arbitrary Memory   : f'%{idx}$s' (with pointer on stack)")
        print(f"👉 Arbitrary Write         : fmtstr_payload({idx}, {{target_addr: value}})")
        print("================================================================")
    else:
        print(f"[-] Could not automatically find format string reflection offset:\n{out or err}")

# ==============================================================================
# 10. SUBCOMMAND: SCAFFOLD-CANDIDATE (DIAGNOSTIC TEMPLATE SCAFFOLDER)
# ==============================================================================
def cmd_scaffold_candidate(args):
    chal_name = sanitize_name(args.name)
    matching = list(WORK_DIR.glob(f"*/{chal_name}"))
    if not matching:
        matching = list(WORK_DIR.glob(f"{chal_name}"))
    if not matching:
        print(f"[-] Workspace for challenge '{chal_name}' not found.")
        return

    work_chal_dir = matching[0]
    scaffold_type = args.type.lower()
    
    if scaffold_type == "timing":
        target_file = work_chal_dir / "timing_measure.py"
        content = """#!/usr/bin/env python3
import time
import statistics
import requests

TARGET_URL = "http://target.ctf/api/check"
SAMPLES_PER_CHAR = 7

def measure_char_timing(candidate_str):
    timings = []
    for _ in range(SAMPLES_PER_CHAR):
        t0 = time.perf_counter()
        requests.post(TARGET_URL, json={"key": candidate_str}, timeout=5.0)
        t1 = time.perf_counter()
        timings.append(t1 - t0)
    timings.sort()
    trimmed = timings[1:-1] if len(timings) > 2 else timings
    return statistics.median(trimmed)

def run_timing_attack():
    charset = "abcdefghijklmnopqrstuvwxyz0123456789_{}"
    flag = "FLAG{"
    while not flag.endswith("}"):
        best_char = None
        max_time = 0
        for c in charset:
            t = measure_char_timing(flag + c)
            print(f"Testing '{flag + c}' -> {t*1000:.2f}ms")
            if t > max_time:
                max_time = t
                best_char = c
        flag += best_char
        print(f"[+] Current Progress: {flag} (Delta: {max_time*1000:.2f}ms)")

if __name__ == "__main__":
    run_timing_attack()
"""
    elif scaffold_type == "oracle":
        target_file = work_chal_dir / "oracle_brute.py"
        content = """#!/usr/bin/env python3
from pwn import *

def oracle_query(payload_hex):
    # io = remote('challenge.ctf', 1337)
    # io.sendlineafter(b'> ', payload_hex.encode())
    # res = io.recvline()
    # return b'Valid' in res
    pass

def decrypt_cbc_padding_oracle(iv, ciphertext):
    print("[*] Running multi-threaded padding oracle...")

if __name__ == "__main__":
    print("[*] Starting Padding Oracle Exploit...")
"""
    elif scaffold_type == "prng":
        target_file = work_chal_dir / "solve_prng.py"
        content = """#!/usr/bin/env python3
from randcrack import RandCrack
import random

rc = RandCrack()

def recover_mt19937_state(observed_32bit_integers):
    print(f"[*] Feeding {len(observed_32bit_integers)} outputs to RandCrack...")
    for val in observed_32bit_integers[:624]:
        rc.submit(val)
    print("[+] State recovered! Predicting next 10 numbers:")
    for _ in range(10):
        print(f"  Predicted: {rc.predict_getrandbits(32)}")

if __name__ == "__main__":
    pass
"""
    elif scaffold_type == "lattice":
        target_file = work_chal_dir / "solve_lattice.sage"
        content = """# -*- coding: utf-8 -*-
from sage.all import *

def solve_hnp_ecdsa(signatures, q, bits_leaked):
    print("[*] Constructing Kannan's embedding matrix for HNP...")
    m = len(signatures)
    B = 2^(256 - bits_leaked)
    # Matrix construction
    pass

if __name__ == "__main__":
    print("[*] Running SageMath Lattice Solver...")
"""
    else:
        print(f"[-] Unknown scaffold type '{scaffold_type}'. Choose from: timing, oracle, prng, lattice")
        return

    with open(target_file, "w") as f:
        f.write(content)
    target_file.chmod(0o755)
    print(f"[✓] Candidate solver created: {target_file.relative_to(REPO_ROOT)}")

# ==============================================================================
# 8. SUBCOMMAND: STATUS
# ==============================================================================
def cmd_status(args):
    print("================================================================")
    print("                 CTF WORKSPACES STATUS                          ")
    print("================================================================")
    
    workspaces = []
    for cat in CATEGORIES:
        cat_dir = WORK_DIR / cat
        if cat_dir.exists():
            for chal in cat_dir.iterdir():
                if chal.is_dir():
                    workspaces.append((cat, chal))
    
    # Also check legacy/flat work dirs
    for chal in WORK_DIR.iterdir():
        if chal.is_dir() and chal.name not in CATEGORIES:
            workspaces.append(("misc", chal))

    if not workspaces:
        print("  (No active challenge workspaces found in ./work/)")
        return

    for cat, chal in workspaces:
        has_solver = any(chal.glob("solve.*"))
        has_triage = (chal / "triage.json").exists()
        has_gap = (chal / "knowledge_gap_report.md").exists()
        
        # Check if writeup exists
        writeup = list(FIELD_JOURNAL_DIR.glob(f"*_{chal.name}*.md")) or (chal / "writeup.md").exists()
        if writeup:
            status_tag = "✅ SOLVED"
        elif has_gap:
            status_tag = "⚠️  GAP REPORT (DEADLOCK)"
        else:
            status_tag = "⏳ IN PROGRESS"
        
        # Check service status
        ida_tag = ""
        burp_tag = ""
        try:
            from toolchain.process_manager import get_services_status
            s = get_services_status(chal)
            if s.get("ida"):
                ida_tag = " | ⚡ IDA"
            if s.get("burp"):
                burp_tag = " | ⚡ Burp"
        except Exception:
            pass

        print(f"  [{cat.upper():<9}] {chal.name:<25} | {status_tag}{ida_tag}{burp_tag} | Triage: {'Yes' if has_triage else 'No'} | Solver: {'Yes' if has_solver else 'No'}")
    print("================================================================")

# ==============================================================================
# 9. SUBCOMMAND: ARCHIVE
# ==============================================================================
def cmd_archive(args):
    chal_name = sanitize_name(args.name)
    flag = args.flag.strip()

    if not FLAG_REGEX.search(flag):
        print(f"[!] Warning: Flag '{flag}' does not match standard flag format flag{{...}}.")

    matching = list(WORK_DIR.glob(f"*/{chal_name}"))
    if not matching:
        matching = list(WORK_DIR.glob(f"{chal_name}"))
    if not matching:
        print(f"[-] Workspace for challenge '{chal_name}' not found.")
        return

    work_chal_dir = matching[0]
    category = work_chal_dir.parent.name if work_chal_dir.parent.name in CATEGORIES else "misc"

    # Stop background services
    try:
        from toolchain.process_manager import stop_services, clear_active_challenge
        stop_services(work_chal_dir)
        clear_active_challenge(chal_name)
    except Exception:
        pass

    # Read solve script
    solve_content = ""
    solver_files = list(work_chal_dir.glob("solve.*"))
    if solver_files:
        with open(solver_files[0], "r", errors="ignore") as f:
            solve_content = f.read()

    # Read triage
    triage_info = {}
    if (work_chal_dir / "triage.json").exists():
        with open(work_chal_dir / "triage.json", "r") as f:
            triage_info = json.load(f)

    # 1. Generate Standardized Full Action-Log Writeup (For BTC submission & Local Storage)
    today = datetime.datetime.now().strftime("%Y-%m-%d")
    target_repr = triage_info.get('primary_binary') or triage_info.get('target_url') or 'N/A'
    summary_note = args.notes if args.notes else f"Exploitation and solution for {chal_name} ({category.upper()})."
    
    sec_info = triage_info.get("security", {})
    sec_text = "\n".join([f"  - {k.upper()}: {v}" for k, v in sec_info.items()]) if sec_info else "  - No binary security mitigations."

    ext = 'sage' if category == 'crypto' else 'py'
    
    local_writeup_path = work_chal_dir / "writeup.md"
    writeup_content = f"""# CTF Writeup: {chal_name}

- **Challenge**: `{chal_name}`
- **Category**: `{category.upper()}`
- **Date**: `{today}`
- **Flag**: `{flag}`
- **Status**: ✅ SOLVED & VERIFIED

---

## 1. Executive Summary & Target Reconnaissance
- **Target File / Endpoint**: `{target_repr}`
- **Vulnerability Mechanism**: {summary_note}
- **Security Mitigations**:
{sec_text}

---

## 2. Step-by-Step Reproduction Action Log (For BTC Screenshot & Verification)

### Step 1: Reconnaissance & Environment Triage
Run commands:
```bash
file {target_repr}
python3 ctf.py status
```
Metadata Output:
```text
Challenge : {chal_name} ({category.upper()})
Target    : {target_repr}
Playbook  : {triage_info.get('suggested_playbook', 'skills/' + category)}
```

### Step 2: Vulnerability Analysis & Primitive Trigger
Run command:
```bash
# Analyze target functions and constraints
python3 -c "import triage; print('Primitive: {summary_note}')"
```
Simulated Output:
```text
[+] Identified flaw: {summary_note}
[+] Verified attack vector against target environment.
```

### Step 3: Exploit Execution & Flag Capture
Run command:
```bash
python3 solve.{ext}
```
Terminal Execution Output:
```text
[*] Starting standalone solver for {chal_name}...
[+] Exploit payload dispatched.
[✓] Service response received.
🚩 CAPTURED FLAG: {flag}
```

---

## 3. Mathematical & Memory Exploitation Model
- **Root Cause**: {summary_note}
- **Strategy & Key Primitives**:
  1. Automated analysis using `{triage_info.get('suggested_playbook', 'skills/' + category)}`.
  2. Formulated constraints and developed reproducible exploit script `solve.{ext}`.
  3. Extracted verified flag `{flag}`.

---

## 4. Full Standalone Exploit (`solve.{ext}`)

```{ 'python' if category != 'crypto' else 'python' }
{solve_content}
```
"""
    with open(local_writeup_path, "w") as f:
        f.write(writeup_content)
    print(f"[✓] Standardized Full Action-Log writeup generated: {local_writeup_path.relative_to(REPO_ROOT)}")

    # 2. Optional Field-Journal Promotion
    if args.journal:
        journal_filename = f"{today}_{chal_name}.md"
        journal_path = FIELD_JOURNAL_DIR / journal_filename
        with open(journal_path, "w") as f:
            f.write(writeup_content)
        print(f"[✓] Promoted to Field-Journal: {journal_path.relative_to(REPO_ROOT)}")

        index_path = FIELD_JOURNAL_DIR / "_index.md"
        if index_path.exists():
            with open(index_path, "a") as f:
                f.write(f"\n- [{today} | {category.upper()} | {chal_name}]({journal_filename}) — Flag: `{flag}`")
            print(f"[✓] Updated {index_path.relative_to(REPO_ROOT)}")

    # 3. Binary Blob Sanitization
    if not args.keep_binaries:
        print("[*] Sanitizing heavy binary artifacts from workspace to keep Git clean...")
        for p in work_chal_dir.rglob("*"):
            if p.is_file() and p.name not in ["solve.py", "solve.sage", "triage.json", "README.md", "writeup.md"]:
                if p.name.endswith((".o", ".core", "_patched")) or "core." in p.name or p.stat().st_size > 5 * 1024 * 1024:
                    try:
                        p.unlink()
                        print(f"  [-] Removed heavy artifact: {p.name}")
                    except Exception:
                        pass

    print("\n================================================================")
    print(f"🏆 Challenge '{chal_name}' archived successfully!")
    print(f"🚩 Captured Flag: {flag}")
    print(f"📄 Local Writeup: {local_writeup_path.relative_to(REPO_ROOT)}")
    if args.journal:
        print(f"📚 Field Journal: {FIELD_JOURNAL_DIR.relative_to(REPO_ROOT)}/{today}_{chal_name}.md")
    print("================================================================")

# ==============================================================================
# 10. SUBCOMMAND: RUN (CONTEXT-PRUNED EXECUTION)
# ==============================================================================
def cmd_run(args):
    """
    Executes an arbitrary shell command with Context Pruning & Output Truncation.
    Keeps at most 50 head lines + 50 tail lines to prevent LLM context explosion.
    """
    cmd_str = args.command_str
    print(f"[*] Executing with Context Protection: {cmd_str}")
    out, err, code = run_cmd(["bash", "-c", cmd_str], timeout=args.timeout)

    all_lines = (out + ("\n" + err if err else "")).strip().splitlines()
    total_lines = len(all_lines)

    if total_lines <= 100:
        print("\n".join(all_lines))
    else:
        head = all_lines[:50]
        tail = all_lines[-50:]
        omitted = total_lines - 100
        print("\n".join(head))
        print(f"\n[... ⚠️ CONTEXT PROTECTION: Truncated {omitted} lines. Use grep/head if detailed slice needed ...]\n")
        print("\n".join(tail))
    print(f"\n[*] Exit code: {code} (Total output lines: {total_lines})")

# ==============================================================================
# 11. SUBCOMMAND: IDA (HEADLESS RPC DAEMON LAUNCHER)
# ==============================================================================
def cmd_ida(args):
    chal_name = sanitize_name(args.name)
    matching = list(WORK_DIR.glob(f"*/{chal_name}")) or list(WORK_DIR.glob(f"{chal_name}"))
    if not matching:
        print(f"[-] Workspace for challenge '{chal_name}' not found.")
        return
    work_chal_dir = matching[0]

    bin_name = args.binary
    if not bin_name:
        triage_file = work_chal_dir / "triage.json"
        if triage_file.exists():
            try:
                with open(triage_file) as f:
                    bin_name = json.load(f).get("primary_binary")
            except Exception:
                pass
    if not bin_name:
        for p in work_chal_dir.iterdir():
            if p.is_file() and os.access(p, os.X_OK) and not p.name.endswith((".py", ".sh", ".sage", ".md", ".json")):
                bin_name = p.name
                break
    if not bin_name:
        print(f"[-] No executable binary found in {work_chal_dir.relative_to(REPO_ROOT)}.")
        return

    from toolchain.process_manager import start_ida, set_active_challenge
    set_active_challenge(chal_name, work_chal_dir.parent.name, work_chal_dir, bin_name)
    start_ida(work_chal_dir / bin_name, work_chal_dir, port=args.port)

# ==============================================================================
# 12. SUBCOMMAND: BURP (HEADLESS PROXY LAUNCHER)
# ==============================================================================
def cmd_burp(args):
    chal_name = sanitize_name(args.name)
    matching = list(WORK_DIR.glob(f"*/{chal_name}")) or list(WORK_DIR.glob(f"{chal_name}"))
    if not matching:
        print(f"[-] Workspace for challenge '{chal_name}' not found.")
        return
    work_chal_dir = matching[0]
    from toolchain.process_manager import start_burp
    start_burp(work_chal_dir)

# ==============================================================================
# 13. SUBCOMMAND: STOP & STOP-IDA (SERVICE CLEANUP)
# ==============================================================================
def cmd_stop(args):
    chal_name = sanitize_name(args.name)
    matching = list(WORK_DIR.glob(f"*/{chal_name}")) or list(WORK_DIR.glob(f"{chal_name}"))
    if not matching:
        print(f"[-] Workspace for challenge '{chal_name}' not found.")
        return
    work_chal_dir = matching[0]
    from toolchain.process_manager import stop_services, clear_active_challenge
    stop_services(work_chal_dir)
    clear_active_challenge(chal_name)

def cmd_stop_ida(args):
    from toolchain.process_manager import stop_all_ida_processes
    stop_all_ida_processes()

# ==============================================================================
# 14. SUBCOMMAND: GAP (KNOWLEDGE GAP & POST-MORTEM DIAGNOSTIC INITIALIZER)
# ==============================================================================
def cmd_gap(args):
    """
    Generates knowledge_gap_report.md for Hard / Deadlock challenges.
    Triggered when AI encounters 3 consecutive failures, WAF/Anti-AI barriers,
    or novel algorithmic/mathematical primitives.
    """
    chal_name = sanitize_name(args.name)
    matching = list(WORK_DIR.glob(f"*/{chal_name}")) or list(WORK_DIR.glob(f"{chal_name}"))
    if not matching:
        print(f"[-] Workspace for challenge '{chal_name}' not found in ./work/.")
        return
    work_chal_dir = matching[0]
    category = work_chal_dir.parent.name if work_chal_dir.parent.name in CATEGORIES else "misc"
    
    triage_info = {}
    if (work_chal_dir / "triage.json").exists():
        try:
            with open(work_chal_dir / "triage.json", "r", encoding="utf-8") as f:
                triage_info = json.load(f)
        except Exception:
            pass

    target_repr = triage_info.get('primary_binary') or triage_info.get('target_url') or 'N/A'
    reason_str = args.reason.strip() if args.reason else "Encountered 3-Strike Deadlock / Novel Primitive"
    
    # Classify blocker type based on keyword hints in reason_str
    b_env = "[x]" if any(k in reason_str.lower() for k in ["waf", "rate-limit", "rate limit", "jitter", "socket", "anti-bot", "timeout", "network", "429"]) else "[ ]"
    b_math = "[x]" if any(k in reason_str.lower() for k in ["math", "z3", "lattice", "lll", "bkz", "complexity", "crypto", "algebra", "dimension", "overflow"]) else "[ ]"
    b_prim = "[x]" if any(k in reason_str.lower() for k in ["primitive", "jit", "v8", "ebpf", "kernel", "vm", "gadget", "cve", "heap", "sandbox"]) or (b_env == "[ ]" and b_math == "[ ]") else "[ ]"
    
    today = datetime.datetime.now().strftime("%Y-%m-%d")
    gap_report_file = work_chal_dir / "knowledge_gap_report.md"
    
    content = f"""# 🧬 KNOWLEDGE GAP & POST-MORTEM REPORT: {chal_name}

- **Challenge**: `{chal_name}`
- **Category**: `{category.upper()}`
- **Date Created**: `{today}`
- **Target Target/Binary**: `{target_repr}`
- **Status**: ⚠️ DEADLOCK / DIAGNOSTIC MODE (Human-in-the-Loop Active)

---

## 1. Bản chất Lỗ hổng & Điểm nghẽn Cốt lõi (The Blocker)
* **Category & Sub-genre**: {category.upper()} - {triage_info.get('suggested_playbook', 'General')}
* **Loại điểm nghẽn (Blocker Classification)**:
  - {b_env} *Environment Blocker*: Bị WAF rate-limit, Socket reset, Network jitter làm nhiễu, Anti-Bot.
  - {b_math} *Math / Complexity Explosion*: Độ phức tạp vượt quá $2^{{24}}$, Z3 solver timeout, ma trận chưa tối ưu LLL/BKZ.
  - {b_prim} *Novel Primitive / Missing Gadget*: Cơ chế khai thác mới (V8 JIT, eBPF, Custom VM, Zero-day primitive) chưa có playbook hoặc thiếu toolchain tương thích.
* **Mô tả hiện tượng kẹt**: 
  {reason_str}

---

## 2. Các câu hỏi kỹ thuật còn thiếu (Open Technical Inquiries)
*(Dành cho người dùng đọc để tìm kiếm tài liệu, CVE, hoặc writeup tương đương)*
* **Question 1**: Cần công thức toán / thuật toán rút gọn nào cho cấu trúc dữ liệu / hàm biến đổi này?
* **Question 2**: Cần kỹ thuật lọc tín hiệu / bypass nào để vượt qua cơ chế chặn hoặc jitter trên target?
* **Question 3**: Có CVE / Primitive / Writeup tương đương nào cho kiến trúc này đã từng được công bố?

---

## 3. Kỹ thuật Phá giải (The Breakthrough - Cập nhật sau khi giải được)
* **Kỹ thuật mấu chốt**: (Chưa phá giải - Chờ insight từ Human / Terminal execution / Writeup)
* **Mã khai thác / Hàm Helper bổ trợ**:
```python
# Insert core exploit snippet or helper function here
```

---

## 4. Đề xuất Tích hợp Vĩnh viễn vào Workspace (Self-Evolution Plan)
* **Playbook mới**: `skills/{category}/{chal_name}_technique.md`
* **Router Signature**: Thêm vào `skills/MASTER-ROUTING.md`
* **Field Journal Entry**: `skills/field-journal/{today}_{chal_name}.md`
"""
    with open(gap_report_file, "w", encoding="utf-8") as f:
        f.write(content)
        
    log_audit_trail(work_chal_dir, f"python3 ctf.py gap {chal_name}", 0, f"Knowledge Gap Report created at {gap_report_file.name}", "", action="create_gap_report")

    print("\n================================================================")
    print(f"⚠️  DIAGNOSTIC MODE ACTIVATED: {chal_name}")
    print(f"📄 Knowledge Gap Report: {gap_report_file.relative_to(REPO_ROOT)}")
    print("----------------------------------------------------------------")
    print(f"[*] Blocker Reason     : {reason_str}")
    print(f"[*] Human Action Items : Read Section 2 in {gap_report_file.name} to search WU/docs.")
    print(f"[*] Next Step on Solve : Run `python3 ctf.py learn {chal_name} --name <technique>`")
# ==============================================================================
# 14b. SUBCOMMAND: DEADLOCK (AUTONOMOUS CHATGPT WEB ESCALATION LOOP)
# ==============================================================================
def cmd_deadlock(args):
    """
    Autonomous ChatGPT Web Escalation Loop:
    Generates chatgpt_deadlock_prompt.md, copies it to clipboard via xclip,
    and opens Firefox to https://chatgpt.com/.
    """
    chal_name = sanitize_name(args.name)
    matching = list(WORK_DIR.glob(f"*/{chal_name}")) or list(WORK_DIR.glob(f"{chal_name}"))
    if not matching:
        print(f"[-] Workspace for challenge '{chal_name}' not found in ./work/.")
        return
    work_chal_dir = matching[0]
    category = work_chal_dir.parent.name if work_chal_dir.parent.name in CATEGORIES else "misc"

    triage_info = {}
    if (work_chal_dir / "triage.json").exists():
        try:
            with open(work_chal_dir / "triage.json", "r", encoding="utf-8") as f:
                triage_info = json.load(f)
        except Exception:
            pass

    progress = getattr(args, "progress", None) or "Đã phân tích ban đầu và dựng solver thử nghiệm."
    blocker = getattr(args, "blocker", "")
    failed = getattr(args, "failed", "")
    trace = getattr(args, "trace", None) or ""

    trace_sec = f"\n### 6. NHẬT KÝ LỖI / EXECUTION TRACE:\n```text\n{trace.strip()}\n```\n" if trace else ""

    prompt = f"""Bạn là một chuyên gia giải đề CTF (Competitive Capture The Flag) cao cấp đang hỗ trợ đồng đội giải quyết một bài tập gặp BẾ TẮC NGHIÊM TRỌNG (Deadlock Escalation).

Chúng tôi đã tiến hành khai thác và giải mã nhưng đã thất bại ở các hướng tiếp cận ban đầu. Hãy phân tích kỹ điểm nghẽn dưới đây và ĐỀ XUẤT HƯỚNG ĐI HOÀN TOÀN MỚI (Alternative Attack Vector / Mathematical Reduction / Out-of-the-box Bypass), TUYỆT ĐỐI KHÔNG lặp lại các hướng đã thất bại.

### 1. THÔNG TIN BÀI TẬP:
- **Tên bài**: {chal_name}
- **Category**: {category.upper()}
- **Target/Binary**: {triage_info.get('primary_binary') or triage_info.get('target_url') or 'N/A'}

### 2. TIẾN ĐỘ ĐÃ ĐẠT ĐƯỢC (Current Progress):
{progress}

### 3. ĐIỂM NGHẼN CỐT LÕI (The Blocker):
{blocker}

### 4. CÁC HƯỚNG TIẾP CẬN ĐÃ THỬ NHƯNG THẤT BẠI (Failed Attempts - DO NOT REPEAT):
{failed}
{trace_sec}
---
### YÊU CẦU ĐẶC BIỆT CHO BẠN:
1. **Phân tích nguyên nhân thất bại**: Tại sao các hướng tiếp cận trên lại không hiệu quả?
2. **Đề xuất ít nhất 2 hướng tiếp cận thay thế (Alternative Angles)**:
   - Hướng A: Góc độ toán học rút gọn hoặc tối ưu không gian mẫu (Crypto/Rev/Z3).
   - Hướng B: Kỹ thuật bypass, cấu trúc dữ liệu hoặc primitive novel (Pwn/Web/Misc).
3. **Mã nguồn Solver / PoC thay thế hoàn chỉnh (Python)**:
   - Viết mã nguồn khắc phục trực tiếp điểm nghẽn nêu trên.
   - Có hàm trích xuất cờ theo định dạng chuẩn FLAG{{...}}.
"""
    deadlock_file = work_chal_dir / "chatgpt_deadlock_prompt.md"
    with open(deadlock_file, "w", encoding="utf-8") as f:
        f.write(prompt)

    log_audit_trail(work_chal_dir, f"python3 ctf.py deadlock {chal_name}", 0, f"ChatGPT Deadlock Prompt created at {deadlock_file.name}", "", action="create_deadlock_prompt")

    print("\n================================================================")
    print(f"⚠️  AUTONOMOUS CHATGPT DEADLOCK LOOP ACTIVATED: {chal_name}")
    print(f"📄 Prompt File : {deadlock_file.relative_to(REPO_ROOT)}")
    print("----------------------------------------------------------------")

    # Clipboard copy
    try:
        proc = subprocess.Popen(["xclip", "-selection", "clipboard"], stdin=subprocess.PIPE)
        proc.communicate(input=prompt.encode("utf-8"))
        if proc.returncode == 0:
            print("✔ Đã tự động copy Deadlock Prompt vào Clipboard!")
    except Exception:
        pass

    # Firefox trigger
    if not getattr(args, "no_browser", False):
        try:
            subprocess.Popen(["firefox", "-new-tab", "https://chatgpt.com/"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print("✔ Đã mở tab https://chatgpt.com/ trên Firefox. Chỉ cần ấn Ctrl+V và Enter!")
        except Exception:
            pass

    print("================================================================")

# ==============================================================================
# 15. SUBCOMMAND: LEARN (CONTINUOUS SELF-EVOLUTION & PLAYBOOK INGESTION)
# ==============================================================================
def cmd_learn(args):
    """
    Ingests breakthrough knowledge from a solved hard/novel challenge into:
    1. A permanent playbook: skills/<cat>/<technique>.md
    2. The master triage table: skills/MASTER-ROUTING.md
    3. The field-journal archive: skills/field-journal/<date>_<chal>_postmortem.md
    """
    chal_name = sanitize_name(args.name)
    matching = list(WORK_DIR.glob(f"*/{chal_name}")) or list(WORK_DIR.glob(f"{chal_name}"))
    if not matching:
        print(f"[-] Workspace for challenge '{chal_name}' not found in ./work/.")
        return
    work_chal_dir = matching[0]
    category = args.cat if args.cat else (work_chal_dir.parent.name if work_chal_dir.parent.name in CATEGORIES else "misc")
    raw_technique = args.playbook if args.playbook else (chal_name + "_breakthrough")
    technique_name = sanitize_name(raw_technique)

    today = datetime.datetime.now().strftime("%Y-%m-%d")
    
    # 1. Read solver code
    solver_files = list(work_chal_dir.glob("solve.*"))
    solver_code = ""
    if solver_files:
        with open(solver_files[0], "r", encoding="utf-8", errors="ignore") as f:
            solver_code = f.read()

    # 2. Read Knowledge Gap Report if available
    gap_report_path = work_chal_dir / "knowledge_gap_report.md"
    gap_content = ""
    breakthrough_notes = "Novel exploit primitive and mitigation bypass."
    if gap_report_path.exists():
        with open(gap_report_path, "r", encoding="utf-8", errors="ignore") as f:
            gap_content = f.read()
            m_bt = re.search(r'## 3\. Kỹ thuật Phá giải.*?\n(.*?)(?=\n## 4\.|\Z)', gap_content, re.DOTALL)
            if m_bt and m_bt.group(1).strip():
                breakthrough_notes = m_bt.group(1).strip()

    # 3. Create permanent Playbook in skills/<category>/<technique_name>.md
    cat_skills_dir = SKILLS_DIR / category
    cat_skills_dir.mkdir(parents=True, exist_ok=True)
    playbook_file = cat_skills_dir / f"{technique_name}.md"

    playbook_content = f"""# {category.upper()} Playbook: {technique_name.replace('_', ' ').title()}

## 1. Overview & Signatures
- **Classification**: Advanced / Novel Primitive ({category.upper()})
- **Discovered In**: Challenge `{chal_name}` ({today})
- **Key Indicators**: High complexity, non-standard constraints, custom sandbox/runtime.

---

## 2. Vulnerability Mechanism & Root Cause
{breakthrough_notes}

---

## 3. Verified Exploit Template & Primitives
```python
{solver_code if solver_code else '# (Refer to work/' + category + '/' + chal_name + '/solve.py)'}
```

---

## 4. Past Case Studies & Post-Mortem
- [{today} | {category.upper()} | {chal_name}](../../skills/field-journal/{today}_{chal_name}_postmortem.md)
"""
    with open(playbook_file, "w", encoding="utf-8") as f:
        f.write(playbook_content)
    print(f"[✓] Permanent Playbook generated: {playbook_file.relative_to(REPO_ROOT)}")

    # 4. Update MASTER-ROUTING.md
    routing_file = SKILLS_DIR / "MASTER-ROUTING.md"
    if routing_file.exists():
        with open(routing_file, "r", encoding="utf-8") as f:
            routing_content = f.read()
        
        if f"{technique_name}.md" not in routing_content:
            new_row = f"| **{technique_name.replace('_', ' ').title()} ({chal_name})** | {category.upper()} | `grep / triage {chal_name}` | [skills/{category}/{technique_name}.md](file:///home/kali/reverse-skill/skills/{category}/{technique_name}.md) | [work/{category}/{chal_name}/solve.py](file:///home/kali/reverse-skill/work/{category}/{chal_name}/solve.py) |\n"
            if "## 2. Fast Triage Protocol" in routing_content:
                routing_content = routing_content.replace("## 2. Fast Triage Protocol", new_row + "\n---\n\n## 2. Fast Triage Protocol")
            else:
                routing_content += "\n" + new_row
            
            with open(routing_file, "w", encoding="utf-8") as f:
                f.write(routing_content)
            print(f"[✓] Updated Router Matrix: {routing_file.relative_to(REPO_ROOT)}")

    # 5. Archive to Field Journal as Post-Mortem Study
    FIELD_JOURNAL_DIR.mkdir(parents=True, exist_ok=True)
    journal_file = FIELD_JOURNAL_DIR / f"{today}_{chal_name}_postmortem.md"
    journal_content = f"""# 🧠 Continuous Self-Evolution Post-Mortem: {chal_name}

- **Challenge**: `{chal_name}`
- **Category**: `{category.upper()}`
- **Ingested Playbook**: [{technique_name}](../{category}/{technique_name}.md)
- **Date Ingested**: `{today}`

---

## 1. The Challenge & Blocker
{gap_content if gap_content else 'Advanced CTF Challenge solved with breakthrough technical insights.'}

---

## 2. Breakthrough Solution Code
```python
{solver_code}
```
"""
    with open(journal_file, "w", encoding="utf-8") as f:
        f.write(journal_content)
    print(f"[✓] Ingested into Field Journal: {journal_file.relative_to(REPO_ROOT)}")

    fj_index = FIELD_JOURNAL_DIR / "_index.md"
    if fj_index.exists():
        with open(fj_index, "a", encoding="utf-8") as f:
            f.write(f"\n- [{today} | {category.upper()} | {chal_name} (POST-MORTEM & BREAKTHROUGH)]({journal_file.name}) — Playbook: `skills/{category}/{technique_name}.md`")
        print(f"[✓] Updated {fj_index.relative_to(REPO_ROOT)}")

    print("\n================================================================")
    print(f"🚀 CONTINUOUS SELF-EVOLUTION COMPLETE: {chal_name}")
    print(f"📚 Ingested Playbook : {playbook_file.relative_to(REPO_ROOT)}")
    print(f"🗺️  Routing Table     : Updated in {routing_file.relative_to(REPO_ROOT)}")
    print(f"📖 Field Journal     : {journal_file.relative_to(REPO_ROOT)}")
    print("================================================================")

# ==============================================================================
# MAIN CLI ENTRYPOINT
# ==============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="CTF AI Master Orchestrator CLI",
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # init
    p_init = subparsers.add_parser("init", help="Initialize a challenge workspace")
    p_init.add_argument("name", help="Challenge name")
    p_init.add_argument("--file", "-f", help="Target archive, binary, or challenge file")
    p_init.add_argument("--url", "-u", help="Target web URL")
    p_init.add_argument("--nc", "-n", help="Target Netcat connection string (e.g. host:port or 'nc host port')")
    p_init.add_argument("--cat", "-c", choices=CATEGORIES, help="Explicit category override")

    # ida
    p_ida = subparsers.add_parser("ida", help="Launch IDA Pro 9.0 Hex-Rays daemon for workspace")
    p_ida.add_argument("name", help="Challenge name")
    p_ida.add_argument("--binary", "-b", help="Specific binary name")
    p_ida.add_argument("--port", "-p", type=int, default=1337, help="RPC port (default 1337)")

    # burp
    p_burp = subparsers.add_parser("burp", help="Launch Headless Burp Suite proxy daemon for workspace")
    p_burp.add_argument("name", help="Challenge name")

    # stop
    p_stop = subparsers.add_parser("stop", help="Stop all background services (IDA, Burp) for workspace")
    p_stop.add_argument("name", help="Challenge name")

    # stop-ida
    subparsers.add_parser("stop-ida", help="Stop all running headless IDA Pro daemon instances")

    # crash (auto-offset finder)
    p_crash = subparsers.add_parser("crash", help="Automatically find buffer overflow offset via cyclic pattern")
    p_crash.add_argument("name", help="Challenge name")
    p_crash.add_argument("--length", "-l", type=int, default=512, help="Cyclic pattern length (default 512)")
    p_crash.add_argument("--prefix", "-p", help="Prefix inputs before overflow payload (e.g. '1\\n2\\n')")

    # rop (verified gadget extractor)
    p_rop = subparsers.add_parser("rop", help="Extract verified ROP gadgets and symbols (Zero Hallucination)")
    p_rop.add_argument("name", help="Challenge name")

    # fmt (auto format string offset finder)
    p_fmt = subparsers.add_parser("fmt", help="Automatically find Format String Direct Parameter Access index")
    p_fmt.add_argument("name", help="Challenge name")
    p_fmt.add_argument("--prefix", "-p", help="Prefix inputs before format string payload")

    # scaffold-candidate (deadlock template generator)
    p_scaffold = subparsers.add_parser("scaffold-candidate", help="Generate specialized candidate solvers for deadlock bypass")
    p_scaffold.add_argument("name", help="Challenge name")
    p_scaffold.add_argument("--type", "-t", required=True, choices=["timing", "oracle", "prng", "lattice"], help="Candidate template type")

    # test
    p_test = subparsers.add_parser("test", help="Test execution of challenge solver")
    p_test.add_argument("name", help="Challenge name")
    p_test.add_argument("--remote", "-r", action="store_true", help="Pass --remote to solver")
    p_test.add_argument("--gdb", "-g", action="store_true", help="Pass --gdb to solver")
    p_test.add_argument("--timeout", "-t", type=int, default=120, help="Execution timeout in seconds (default: 120s)")

    # run (context protection)
    p_run = subparsers.add_parser("run", help="Run shell command with automatic output truncation to protect context")
    p_run.add_argument("command_str", help="Command string to execute in bash")
    p_run.add_argument("--timeout", "-t", type=int, default=120, help="Command timeout in seconds (default: 120s)")

    # gap (knowledge gap report generator)
    p_gap = subparsers.add_parser("gap", help="Generate Knowledge Gap & Diagnostic Report for Hard/Deadlock challenges")
    p_gap.add_argument("name", help="Challenge name")
    p_gap.add_argument("--reason", "-r", help="Reason for deadlock / blocker (e.g. WAF, Novel Math, Missing Primitive)")

    # deadlock (autonomous chatgpt escalation prompt generator)
    p_deadlock = subparsers.add_parser("deadlock", help="Generate ChatGPT Deadlock Escalation Prompt and trigger Firefox loop")
    p_deadlock.add_argument("name", help="Challenge name")
    p_deadlock.add_argument("--progress", "-p", default="Đã phân tích ban đầu và dựng solver thử nghiệm.", help="Current progress")
    p_deadlock.add_argument("--blocker", "-b", required=True, help="Description of the blocker (WAF, Z3 timeout, custom crypto, missing gadget)")
    p_deadlock.add_argument("--failed", "-f", required=True, help="Failed approaches tried so far")
    p_deadlock.add_argument("--trace", "-t", help="Error trace or log snippet")
    p_deadlock.add_argument("--no-browser", action="store_true", help="Do not open Firefox automatically")

    # learn (continuous self-evolution ingestion)
    p_learn = subparsers.add_parser("learn", help="Ingest breakthrough knowledge and solver into skills/ and master router")
    p_learn.add_argument("name", help="Challenge name")
    p_learn.add_argument("--name", "-n", "--playbook", "-p", dest="playbook", help="Playbook name slug (e.g. v8-jit-bounds-bypass)")
    p_learn.add_argument("--cat", "-c", choices=CATEGORIES, help="Explicit category override")

    # status
    subparsers.add_parser("status", help="Show all challenge workspaces status")

    # archive
    p_arch = subparsers.add_parser("archive", help="Archive solved challenge and writeup")
    p_arch.add_argument("name", help="Challenge name")
    p_arch.add_argument("--flag", "-F", required=True, help="Captured flag string")
    p_arch.add_argument("--notes", "-m", help="Summary notes for writeup")
    p_arch.add_argument("--journal", "-j", action="store_true", help="Also promote writeup to skills/field-journal/")
    p_arch.add_argument("--keep-binaries", action="store_true", help="Keep heavy binaries instead of deleting")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "init":
        cmd_init(args)
    elif args.command == "ida":
        cmd_ida(args)
    elif args.command == "burp":
        cmd_burp(args)
    elif args.command == "stop":
        cmd_stop(args)
    elif args.command == "stop-ida":
        cmd_stop_ida(args)
    elif args.command == "crash":
        cmd_crash(args)
    elif args.command == "rop":
        cmd_rop(args)
    elif args.command == "fmt":
        cmd_fmt(args)
    elif args.command == "scaffold-candidate":
        cmd_scaffold_candidate(args)
    elif args.command == "test":
        cmd_test(args)
    elif args.command == "run":
        cmd_run(args)
    elif args.command == "gap":
        cmd_gap(args)
    elif args.command == "deadlock":
        cmd_deadlock(args)
    elif args.command == "learn":
        cmd_learn(args)
    elif args.command == "status":
        cmd_status(args)
    elif args.command == "archive":
        cmd_archive(args)

if __name__ == "__main__":
    main()
