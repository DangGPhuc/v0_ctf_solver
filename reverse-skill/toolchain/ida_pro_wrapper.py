#!/usr/bin/env python3
"""
IDA Pro Smart FastMCP Bridge Wrapper
Provides On-Demand / Lazy-Loading MCP integration for IDA Pro 9.0 Hex-Rays.

Behavior:
1. On Startup: Instantly registers and exposes all IDA analysis tools over stdio without crashing.
2. On Tool Call: Automatically detects if IDA XML-RPC is running. If not, auto-detects the active
   challenge binary and launches IDA Pro headless (idat) in the background, waits for readiness,
   and proxies the request.
3. Standby Mode: If no binary is being analyzed, returns a friendly status message rather than crashing.
"""

import os
import sys
import time
import xmlrpc.client
from pathlib import Path
from mcp.server.fastmcp import FastMCP

# Add repo root to path for toolchain imports
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    from toolchain.process_manager import (
        is_ida_rpc_alive,
        get_active_challenge,
        start_ida,
        stop_all_ida_processes
    )
except ImportError:
    # Fallback if imported from elsewhere
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from process_manager import (
        is_ida_rpc_alive,
        get_active_challenge,
        start_ida,
        stop_all_ida_processes
    )

PORT = int(os.environ.get("IDA_RPC_PORT", "1337"))
RPC_URL = f"http://127.0.0.1:{PORT}"

mcp = FastMCP(
    "ida-pro",
    dependencies=["mcp"]
)

def get_rpc_client():
    return xmlrpc.client.ServerProxy(RPC_URL, allow_none=True)

def ensure_ida_ready(max_wait_seconds: float = 25.0) -> tuple[bool, str]:
    """
    Ensure the IDA Pro headless XML-RPC daemon is running.
    If not running, attempts to auto-launch it on the active challenge binary.
    Returns (success: bool, status_or_error_msg: str).
    """
    if is_ida_rpc_alive(port=PORT, timeout=0.3):
        return True, "IDA daemon active."

    # Need to auto-launch IDA
    active_chal = get_active_challenge()
    if not active_chal:
        return False, (
            "IDA Pro is currently in Standby (no active binary loaded).\n"
            "To activate IDA, run: python3 ctf.py init <chal_name> --file <binary> (cat: rev/pwn)\n"
            "Or launch manually with: python3 ctf.py ida <chal_name>"
        )

    bin_path = active_chal.get("binary_path")
    work_dir = active_chal.get("work_dir")
    chal_name = active_chal.get("name", "unknown")

    if not bin_path or not Path(bin_path).exists():
        return False, (
            f"IDA Pro Standby: Active challenge '{chal_name}' does not have a valid binary at '{bin_path}'.\n"
            "Please initialize or supply the binary file using 'python3 ctf.py init <name> --file <binary>'."
        )

    print(f"[*] On-Demand Trigger: Auto-launching IDA Pro for challenge '{chal_name}' ({Path(bin_path).name})...", file=sys.stderr)
    start_ida(bin_path, work_dir, port=PORT)

    # Poll for daemon availability
    start_time = time.time()
    while time.time() - start_time < max_wait_seconds:
        if is_ida_rpc_alive(port=PORT, timeout=0.5):
            print(f"[✓] IDA Pro XML-RPC Daemon is ready for '{chal_name}'.", file=sys.stderr)
            return True, f"IDA daemon ready for '{chal_name}'."
        time.sleep(0.5)

    return False, (
        f"Timed out after {max_wait_seconds}s waiting for IDA Pro daemon to analyze '{Path(bin_path).name}'.\n"
        f"Check logs at: {Path(work_dir) / '.ida.log'}"
    )

@mcp.tool()
def ida_ping() -> str:
    """Check if IDA Pro XML-RPC daemon is running, responsive, and check binary status."""
    ok, msg = ensure_ida_ready(max_wait_seconds=8.0)
    if not ok:
        return f"IDA Pro Status: STANDBY\n{msg}"

    try:
        client = get_rpc_client()
        res = client.ping()
        return (
            f"IDA Pro Status: OK (Active)\n"
            f"Target Binary : {res.get('file')}\n"
            f"Architecture  : {res.get('arch')} ({'64-bit' if res.get('is_64bit') else '32-bit'})\n"
            f"Hex-Rays Decompiler: {'Available' if res.get('hexrays') else 'Disabled'}"
        )
    except Exception as e:
        return f"ERROR communicating with IDA Pro Daemon at {RPC_URL}: {e}"

@mcp.tool()
def ida_get_info() -> str:
    """Retrieve detailed binary metadata, segments, image base, and entry points from IDA Pro."""
    ok, msg = ensure_ida_ready()
    if not ok:
        return f"[IDA Standby] {msg}"

    try:
        client = get_rpc_client()
        info = client.get_info()
        if "error" in info:
            return f"Error: {info['error']}"
        
        output = [
            f"=== Binary Analysis Info ===",
            f"File: {info.get('root_file')}",
            f"Image Base: {info.get('image_base')}",
            f"Function Count: {info.get('function_count')}",
            "\n--- Segments ---"
        ]
        for seg in info.get("segments", []):
            s_name = str(seg.get('name') or '')
            s_start = str(seg.get('start') or '')
            s_end = str(seg.get('end') or '')
            s_perm = str(seg.get('perm') or '')
            output.append(f"  {s_name:<12} {s_start} - {s_end} (perm: {s_perm})")
        
        output.append("\n--- Entry Points ---")
        for ent in info.get("entries", []):
            e_name = str(ent.get('name') or '')
            e_ea = str(ent.get('ea') or '')
            output.append(f"  {e_name:<20} @ {e_ea}")
            
        return "\n".join(output)
    except Exception as e:
        return f"Error connecting to IDA daemon: {str(e)}"

@mcp.tool()
def ida_list_functions() -> str:
    """List all analyzed functions in the binary with start and end addresses."""
    ok, msg = ensure_ida_ready()
    if not ok:
        return f"[IDA Standby] {msg}"

    try:
        client = get_rpc_client()
        funcs = client.list_functions()
        if not funcs:
            return "No functions found or IDA analysis still in progress."
        
        lines = [f"Total Functions: {len(funcs)}", f"{'Function Name':<35} {'Start EA':<18} {'End EA':<18}"]
        lines.append("-" * 75)
        for f in funcs:
            fname = str(f.get('name') or 'unknown')
            fstart = str(f.get('start_ea') or '')
            fend = str(f.get('end_ea') or '')
            lines.append(f"{fname:<35} {fstart:<18} {fend:<18}")
        return "\n".join(lines)
    except Exception as e:
        return f"Error querying IDA functions: {str(e)}"

@mcp.tool()
def ida_decompile(ea_or_name: str) -> str:
    """
    Decompile a function into clean C pseudocode using Hex-Rays.
    Accepts function name (e.g. 'main', 'vuln', 'check_flag', 'verify') or hex address ('0x401122').
    """
    ok, msg = ensure_ida_ready()
    if not ok:
        return f"[IDA Standby] {msg}"

    try:
        client = get_rpc_client()
        res = client.decompile(ea_or_name)
        if "error" in res:
            return f"Decompilation Error: {res['error']}"
        
        return (
            f"/* Decompiled Function: {res.get('func_name')} @ {res.get('ea')} */\n\n"
            f"{res.get('pseudocode')}"
        )
    except Exception as e:
        return f"Error executing decompilation: {str(e)}"

@mcp.tool()
def ida_get_strings(min_len: int = 4) -> str:
    """Extract string literals found within the binary."""
    ok, msg = ensure_ida_ready()
    if not ok:
        return f"[IDA Standby] {msg}"

    try:
        client = get_rpc_client()
        strings = client.list_strings(min_len)
        if not strings:
            return "No strings extracted."
        
        lines = [f"Extracted {len(strings)} strings (min_length={min_len}):", f"{'Address':<18} {'Length':<8} {'String Content'}"]
        lines.append("-" * 70)
        for s in strings:
            clean_str = repr(s['string'])[1:-1]
            lines.append(f"{s['ea']:<18} {s['length']:<8} {clean_str}")
        return "\n".join(lines)
    except Exception as e:
        return f"Error extracting strings: {str(e)}"

@mcp.tool()
def ida_get_xrefs(ea_or_name: str) -> str:
    """Find all code and data cross-references (Xrefs) to a function or address."""
    ok, msg = ensure_ida_ready()
    if not ok:
        return f"[IDA Standby] {msg}"

    try:
        client = get_rpc_client()
        xrefs = client.get_xrefs_to(ea_or_name)
        if not xrefs:
            return f"No cross-references found pointing to '{ea_or_name}'."
        
        lines = [f"Xrefs to '{ea_or_name}':", f"{'From Address':<18} {'Type':<8} {'Code/Data':<10} {'Caller Function'}"]
        lines.append("-" * 65)
        for x in xrefs:
            lines.append(f"{x['from_ea']:<18} {x['type']:<8} {'Code' if x['is_code'] else 'Data':<10} {x['func_name']}")
        return "\n".join(lines)
    except Exception as e:
        return f"Error querying Xrefs: {str(e)}"

@mcp.tool()
def ida_rename_symbol(ea_or_name: str, new_name: str) -> str:
    """Rename a function, variable, or label at the specified address."""
    ok, msg = ensure_ida_ready()
    if not ok:
        return f"[IDA Standby] {msg}"

    try:
        client = get_rpc_client()
        res = client.rename_symbol(ea_or_name, new_name)
        if "error" in res:
            return f"Rename Error: {res['error']}"
        return f"Successfully renamed symbol at {res.get('ea')} to '{res.get('new_name')}'."
    except Exception as e:
        return f"Error renaming symbol: {str(e)}"

@mcp.tool()
def ida_get_bytes(ea_or_name: str, length: int = 64) -> str:
    """Read raw memory/binary bytes from an address or function name."""
    ok, msg = ensure_ida_ready()
    if not ok:
        return f"[IDA Standby] {msg}"

    try:
        client = get_rpc_client()
        res = client.get_bytes(ea_or_name, length)
        if "error" in res:
            return f"Error: {res['error']}"
        return (
            f"Bytes at {res.get('ea')} (Length: {res.get('length')}):\n"
            f"Hex   : {res.get('hex')}\n"
            f"ASCII : {res.get('ascii')}"
        )
    except Exception as e:
        return f"Error reading bytes: {str(e)}"

@mcp.tool()
def ida_py_eval(code_str: str) -> str:
    """
    Execute an arbitrary IDAPython expression or script snippet directly inside IDA Pro.
    Provides complete low-level access to ida_bytes, ida_funcs, ida_typeinf, etc.
    """
    ok, msg = ensure_ida_ready()
    if not ok:
        return f"[IDA Standby] {msg}"

    try:
        client = get_rpc_client()
        res = client.py_eval(code_str)
        if "error" in res:
            return f"IDAPython Execution Error: {res['error']}"
        out = []
        if res.get("result"):
            out.append(f"Result: {res.get('result')}")
        if res.get("stdout"):
            out.append(f"Output:\n{res.get('stdout')}")
        return "\n".join(out) if out else "Execution completed (no return value)."
    except Exception as e:
        return f"Error evaluating IDAPython snippet: {str(e)}"

if __name__ == "__main__":
    mcp.run(transport="stdio")
