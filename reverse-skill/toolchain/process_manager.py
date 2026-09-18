#!/usr/bin/env python3
"""
Process Orchestrator for Headless IDA Pro and Burp Suite Daemons.
Manages headless service lifecycles, PID files, and automated background execution.
"""

import os
import sys
import json
import signal
import socket
import subprocess
import time
import xmlrpc.client
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
IDA_DAEMON_SCRIPT = REPO_ROOT / "toolchain" / "mcp_servers" / "ida_rpc_daemon.py"
ACTIVE_CHALLENGE_FILE = REPO_ROOT / "work" / ".active_challenge.json"

def find_ida_executable():
    """Locate IDA Pro 9.0 idat headless binary."""
    custom_path = os.environ.get("IDA_PATH")
    candidates = []
    if custom_path:
        candidates.extend([
            Path(custom_path) / "idat",
            Path(custom_path) / "idat64",
            Path(custom_path)
        ])
    candidates.extend([
        REPO_ROOT / "toolchain" / "ida_pro" / "idat",
        Path("/home/kali/ida-pro-9.0/idat"),
        Path("/home/kali/ida-pro-9.0/idat64"),
        Path("/usr/local/bin/idat"),
        Path("/usr/bin/idat")
    ])
    for c in candidates:
        if c.exists() and os.access(c, os.X_OK):
            return str(c)
    return "idat"

def find_burp_jar():
    """Locate Burp Suite JAR package."""
    candidates = [
        REPO_ROOT / "toolchain" / "burpsuite" / "burpsuite.jar",
        Path("/usr/share/burpsuite/burpsuite.jar"),
        Path("/opt/burpsuite/burpsuite.jar")
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return None

def is_pid_alive(pid: int) -> bool:
    """Check if process with given PID is still running."""
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False

def is_ida_rpc_alive(port: int = 1337, timeout: float = 0.5) -> bool:
    """Check if IDA XML-RPC daemon is responding on port."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            pass
        # Further verify XML-RPC response
        client = xmlrpc.client.ServerProxy(f"http://127.0.0.1:{port}", allow_none=True)
        res = client.ping()
        return isinstance(res, dict) and res.get("status") == "ok"
    except Exception:
        return False

def set_active_challenge(chal_name: str, category: str, work_dir: str | Path, binary_name: str | None = None):
    """Record active challenge state for on-demand lazy loading."""
    work_dir = Path(work_dir).resolve()
    binary_path = (work_dir / binary_name).resolve() if binary_name else None
    
    data = {
        "name": chal_name,
        "category": category,
        "work_dir": str(work_dir),
        "binary_name": binary_name,
        "binary_path": str(binary_path) if binary_path and binary_path.exists() else None,
        "timestamp": time.time()
    }
    ACTIVE_CHALLENGE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(ACTIVE_CHALLENGE_FILE, "w") as f:
        json.dump(data, f, indent=2)

def clear_active_challenge(chal_name: str | None = None):
    """Clear active challenge metadata if matching or unconditional."""
    if not ACTIVE_CHALLENGE_FILE.exists():
        return
    try:
        if chal_name:
            with open(ACTIVE_CHALLENGE_FILE, "r") as f:
                data = json.load(f)
            if data.get("name") != chal_name:
                return
        ACTIVE_CHALLENGE_FILE.unlink(missing_ok=True)
    except Exception:
        pass

def get_active_challenge() -> dict | None:
    """Retrieve current active challenge info, or auto-detect from recent work dirs."""
    if ACTIVE_CHALLENGE_FILE.exists():
        try:
            with open(ACTIVE_CHALLENGE_FILE, "r") as f:
                data = json.load(f)
            work_dir = Path(data.get("work_dir", ""))
            if work_dir.exists():
                bin_path = data.get("binary_path")
                if bin_path and Path(bin_path).exists():
                    return data
                # Check if we can find any binary in work_dir
                for p in work_dir.iterdir():
                    if p.is_file() and os.access(p, os.X_OK) and not p.name.endswith((".py", ".sh", ".sage", ".md", ".json")):
                        data["binary_name"] = p.name
                        data["binary_path"] = str(p.resolve())
                        return data
        except Exception:
            pass

    # Fallback: Find most recently modified challenge directory in work/
    work_dir_root = REPO_ROOT / "work"
    candidate_dirs = []
    if work_dir_root.exists():
        for cat_dir in work_dir_root.iterdir():
            if cat_dir.is_dir() and not cat_dir.name.startswith("."):
                for chal_dir in cat_dir.iterdir():
                    if chal_dir.is_dir() and not chal_dir.name.startswith("."):
                        candidate_dirs.append(chal_dir)
                if not candidate_dirs and cat_dir.is_dir():
                    # check flat structure
                    candidate_dirs.append(cat_dir)

    if candidate_dirs:
        candidate_dirs.sort(key=lambda d: d.stat().st_mtime, reverse=True)
        for cdir in candidate_dirs:
            # Look for binary in cdir
            triage_file = cdir / "triage.json"
            bin_name = None
            if triage_file.exists():
                try:
                    with open(triage_file) as f:
                        bin_name = json.load(f).get("primary_binary")
                except Exception:
                    pass
            if bin_name and (cdir / bin_name).exists():
                return {
                    "name": cdir.name,
                    "category": cdir.parent.name,
                    "work_dir": str(cdir),
                    "binary_name": bin_name,
                    "binary_path": str((cdir / bin_name).resolve()),
                    "timestamp": cdir.stat().st_mtime
                }
            for p in cdir.iterdir():
                if p.is_file() and os.access(p, os.X_OK) and not p.name.endswith((".py", ".sh", ".sage", ".md", ".json")):
                    return {
                        "name": cdir.name,
                        "category": cdir.parent.name,
                        "work_dir": str(cdir),
                        "binary_name": p.name,
                        "binary_path": str(p.resolve()),
                        "timestamp": cdir.stat().st_mtime
                    }

    return None

def start_ida(binary_path, work_dir, port=1337):
    """
    Launch IDA Pro 9.0 in headless XML-RPC daemon mode for the target binary.
    """
    work_dir = Path(work_dir)
    binary_path = Path(binary_path).resolve()
    
    if not binary_path.exists():
        print(f"[-] Binary path '{binary_path}' does not exist.", file=sys.stderr)
        return None

    pid_file = work_dir / ".ida.pid"
    if pid_file.exists():
        try:
            old_pid = int(pid_file.read_text().strip())
            if is_pid_alive(old_pid):
                return old_pid
        except Exception:
            pass

    idat_bin = find_ida_executable()
    log_file = work_dir / ".ida.log"

    env = os.environ.copy()
    env["IDA_RPC_PORT"] = str(port)
    env["TVHEADLESS"] = "1"

    # IDA headless command: idat -A -S<daemon_script> <binary>
    cmd = [idat_bin, "-A", f"-S{IDA_DAEMON_SCRIPT}", str(binary_path)]
    print(f"[*] Launching Headless IDA Pro 9.0 Daemon on 127.0.0.1:{port} for '{binary_path.name}'...", file=sys.stderr)
    
    with open(log_file, "w") as out:
        proc = subprocess.Popen(
            cmd,
            env=env,
            stdout=out,
            stderr=subprocess.STDOUT,
            cwd=str(work_dir),
            start_new_session=True
        )

    pid_file.write_text(str(proc.pid))
    rel_log = log_file.relative_to(REPO_ROOT) if log_file.is_relative_to(REPO_ROOT) else log_file
    print(f"[✓] Headless IDA started (PID: {proc.pid}). Logs: {rel_log}", file=sys.stderr)
    return proc.pid

def start_burp(work_dir, port=8080):
    """
    Launch Burp Suite in headless mode.
    """
    work_dir = Path(work_dir)
    pid_file = work_dir / ".burp.pid"
    if pid_file.exists():
        try:
            old_pid = int(pid_file.read_text().strip())
            if is_pid_alive(old_pid):
                print(f"[*] Headless Burp Suite already running (PID: {old_pid}).")
                return old_pid
        except Exception:
            pass

    burp_jar = find_burp_jar()
    if not burp_jar:
        print("[!] Burp Suite JAR not found. Skipping Burp daemon start.")
        return None

    log_file = work_dir / ".burp.log"
    cmd = ["java", "-jar", "-Djava.awt.headless=true", burp_jar, "--suppress-jre-check"]
    print(f"[*] Launching Headless Burp Suite Proxy Daemon...")

    with open(log_file, "w") as out:
        proc = subprocess.Popen(
            cmd,
            stdout=out,
            stderr=subprocess.STDOUT,
            cwd=str(work_dir),
            start_new_session=True
        )

    pid_file.write_text(str(proc.pid))
    print(f"[✓] Headless Burp Suite started (PID: {proc.pid}). Logs: {log_file.relative_to(REPO_ROOT) if log_file.is_relative_to(REPO_ROOT) else log_file}")
    return proc.pid

def stop_services(work_dir):
    """
    Terminate all background daemon services (IDA Pro & Burp Suite) for workspace.
    """
    work_dir = Path(work_dir)
    stopped = []
    
    # 1. Stop IDA
    ida_pid_file = work_dir / ".ida.pid"
    if ida_pid_file.exists():
        try:
            pid = int(ida_pid_file.read_text().strip())
            if is_pid_alive(pid):
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.2)
                if is_pid_alive(pid):
                    os.kill(pid, signal.SIGKILL)
                stopped.append(f"IDA Pro (PID {pid})")
        except Exception:
            pass
        finally:
            try:
                ida_pid_file.unlink()
            except Exception:
                pass

    # 2. Stop Burp
    burp_pid_file = work_dir / ".burp.pid"
    if burp_pid_file.exists():
        try:
            pid = int(burp_pid_file.read_text().strip())
            if is_pid_alive(pid):
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.2)
                if is_pid_alive(pid):
                    os.kill(pid, signal.SIGKILL)
                stopped.append(f"Burp Suite (PID {pid})")
        except Exception:
            pass
        finally:
            try:
                burp_pid_file.unlink()
            except Exception:
                pass

    if stopped:
        print(f"[✓] Stopped background services for {work_dir.name}: {', '.join(stopped)}")

def stop_all_ida_processes():
    """
    Find and kill all running headless IDA Pro processes across all workspaces.
    """
    killed = 0
    work_dir_root = REPO_ROOT / "work"
    if work_dir_root.exists():
        for pid_file in work_dir_root.rglob(".ida.pid"):
            try:
                pid = int(pid_file.read_text().strip())
                if is_pid_alive(pid):
                    os.kill(pid, signal.SIGTERM)
                    time.sleep(0.2)
                    if is_pid_alive(pid):
                        os.kill(pid, signal.SIGKILL)
                    killed += 1
            except Exception:
                pass
            finally:
                pid_file.unlink(missing_ok=True)

    # Subprocess fallback: kill any remaining idat with ida_rpc_daemon
    try:
        out = subprocess.check_output(["pgrep", "-f", "ida_rpc_daemon"], text=True).strip()
        if out:
            for pid_str in out.split():
                try:
                    p = int(pid_str)
                    os.kill(p, signal.SIGKILL)
                    killed += 1
                except Exception:
                    pass
    except Exception:
        pass

    clear_active_challenge()
    print(f"[✓] Stopped all headless IDA processes (Terminated: {killed} instances).")

def get_services_status(work_dir):
    """Check running status of services in a challenge workspace."""
    work_dir = Path(work_dir)
    status = {"ida": False, "burp": False}
    
    ida_pid_file = work_dir / ".ida.pid"
    if ida_pid_file.exists():
        try:
            pid = int(ida_pid_file.read_text().strip())
            status["ida"] = is_pid_alive(pid)
        except Exception:
            pass

    burp_pid_file = work_dir / ".burp.pid"
    if burp_pid_file.exists():
        try:
            pid = int(burp_pid_file.read_text().strip())
            status["burp"] = is_pid_alive(pid)
        except Exception:
            pass

    return status

if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "ida":
        start_ida(sys.argv[2], Path("."))
    elif len(sys.argv) > 1 and sys.argv[1] == "burp":
        start_burp(Path("."))
    elif len(sys.argv) > 1 and sys.argv[1] == "stop-ida":
        stop_all_ida_processes()
    elif len(sys.argv) > 2 and sys.argv[1] == "stop":
        stop_services(Path(sys.argv[2]))
    else:
        print("Usage: process_manager.py [ida <binary> | burp | stop <dir> | stop-ida]")
