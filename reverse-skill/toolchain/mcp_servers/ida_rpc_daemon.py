#!/usr/bin/env python3
"""
IDA Pro Headless XML-RPC Daemon
Runs inside IDA Pro 9.0 (via idat / idat64 -A -Sida_rpc_daemon.py <binary>)
Exposes full Hex-Rays Decompiler & Static Analysis APIs on 127.0.0.1:1337
"""

import sys
import os
import json
import xmlrpc.server
from xmlrpc.server import SimpleXMLRPCServer

# IDA Pro modules
try:
    import ida_auto
    import ida_hexrays
    import ida_funcs
    import ida_nalt
    import ida_bytes
    import ida_name
    import ida_lines
    import ida_xref
    import ida_segment
    import ida_idaapi
    import ida_ida
    import idautils
    import idaapi
    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False

PORT = int(os.environ.get("IDA_RPC_PORT", "1337"))

def resolve_ea(ea_or_name):
    """Convert function name, hex string or int to effective address (ea_t)."""
    if isinstance(ea_or_name, int):
        return ea_or_name
    if isinstance(ea_or_name, str):
        if ea_or_name.startswith("0x") or ea_or_name.startswith("0X"):
            try:
                return int(ea_or_name, 16)
            except ValueError:
                pass
        if ea_or_name.isdigit():
            return int(ea_or_name)
        # Search by symbol name
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, ea_or_name)
        if ea != ida_idaapi.BADADDR:
            return ea
    return ida_idaapi.BADADDR

class IDARpcService:
    def __init__(self):
        self.root_file = ida_nalt.get_root_filename() if IDA_AVAILABLE else "unknown"
        self.hexrays_initialized = False
        if IDA_AVAILABLE:
            try:
                if ida_hexrays.init_hexrays_plugin():
                    self.hexrays_initialized = True
                    print(f"[*] Hex-Rays Decompiler v{ida_hexrays.get_hexrays_version()} initialized successfully.")
                else:
                    print("[!] Hex-Rays plugin could not be initialized.")
            except Exception as e:
                print(f"[!] Hex-Rays init warning: {e}")

    def ping(self):
        """Health check endpoint."""
        is_64 = True
        proc = "unknown"
        try:
            if hasattr(ida_ida, "inf_is_64bit"):
                is_64 = ida_ida.inf_is_64bit()
            if hasattr(ida_ida, "inf_get_procname"):
                proc = ida_ida.inf_get_procname()
        except Exception:
            try:
                inf = ida_idaapi.get_inf_structure() if hasattr(ida_idaapi, "get_inf_structure") else (idaapi.get_inf_structure() if hasattr(idaapi, "get_inf_structure") else None)
                if inf:
                    is_64 = inf.is_64bit() if hasattr(inf, "is_64bit") else True
                    proc = inf.procname if hasattr(inf, "procname") else "unknown"
            except Exception:
                pass

        return {
            "status": "ok",
            "file": self.root_file,
            "arch": proc,
            "is_64bit": is_64,
            "hexrays": self.hexrays_initialized
        }

    def get_info(self):
        """Get binary metadata, segments, and entry points."""
        if not IDA_AVAILABLE:
            return {"error": "IDA Pro environment not available."}
        
        segments = []
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if seg:
                name = ida_segment.get_segm_name(seg)
                segments.append({
                    "name": name,
                    "start": hex(seg.start_ea),
                    "end": hex(seg.end_ea),
                    "perm": seg.perm
                })
        
        entries = []
        try:
            for i, (ea, ord_val, name) in enumerate(idautils.Entries()):
                entries.append({"name": name or f"entry_{i}", "ea": hex(ea)})
        except Exception:
            try:
                import ida_entry
                for i in range(ida_entry.get_entry_qty()):
                    ord_val = ida_entry.get_entry_ordinal(i)
                    ea = ida_entry.get_entry(ord_val)
                    name = ida_entry.get_entry_name(ord_val) or f"entry_{i}"
                    entries.append({"name": name, "ea": hex(ea)})
            except Exception:
                pass

        return {
            "root_file": self.root_file,
            "image_base": hex(ida_nalt.get_imagebase()),
            "segments": segments,
            "entries": entries,
            "function_count": len(list(idautils.Functions()))
        }

    def list_functions(self):
        """List all defined functions with start/end addresses."""
        if not IDA_AVAILABLE:
            return []
        
        funcs = []
        for ea in idautils.Functions():
            f = ida_funcs.get_func(ea)
            if f:
                name = ida_funcs.get_func_name(ea) or f"sub_{hex(f.start_ea)[2:]}"
                funcs.append({
                    "name": str(name),
                    "start_ea": hex(f.start_ea),
                    "end_ea": hex(f.end_ea),
                    "flags": f.flags
                })
        return funcs

    def list_strings(self, min_len=4):
        """Extract all ASCII/Unicode strings from binary."""
        if not IDA_AVAILABLE:
            return []
        
        s_list = []
        try:
            strings = idautils.Strings()
            try:
                strings.setup(strtypes=[ida_nalt.STRTYPE_C, ida_nalt.STRTYPE_C_16], minlen=min_len)
            except Exception:
                try:
                    strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=min_len)
                except Exception:
                    strings.setup(minlen=min_len)
            for s in strings:
                s_val = str(s)
                s_clean = ''.join(c if c.isprintable() or c in '\n\r\t' else f'\\x{ord(c):02x}' for c in s_val)
                s_list.append({
                    "ea": hex(s.ea),
                    "length": s.length,
                    "type": s.strtype,
                    "string": s_clean
                })
                if len(s_list) >= 500:  # Cap at 500 to protect RPC payload
                    break
        except Exception:
            pass
        return s_list

    def decompile(self, ea_or_name):
        """Decompile a function into clean C pseudocode using Hex-Rays."""
        if not IDA_AVAILABLE:
            return {"error": "IDA Pro environment not available."}
        
        ea = resolve_ea(ea_or_name)
        if ea == ida_idaapi.BADADDR:
            return {"error": f"Symbol or address '{ea_or_name}' not found."}
        
        func = ida_funcs.get_func(ea)
        if not func:
            return {"error": f"Address {hex(ea)} is not inside a defined function."}
        
        try:
            hf = ida_hexrays.hexrays_failure_t()
            cfunc = ida_hexrays.decompile(func.start_ea, hf)
            if not cfunc:
                cfunc = ida_hexrays.decompile(ea, hf)
            
            if not cfunc:
                err_msg = hf.desc() if hasattr(hf, "desc") else f"error code {hf.code}"
                return {"error": f"Hex-Rays decompile failed for {hex(func.start_ea)}: {err_msg}"}
            
            lines = []
            sv = cfunc.get_pseudocode()
            for sl in sv:
                lines.append(ida_lines.tag_remove(sl.line))
            
            pseudocode = "\n".join(lines)
            return {
                "status": "ok",
                "func_name": ida_funcs.get_func_name(func.start_ea) or f"sub_{hex(func.start_ea)[2:]}",
                "ea": hex(func.start_ea),
                "pseudocode": pseudocode
            }
        except Exception as e:
            return {"error": f"Decompilation exception: {str(e)}"}

    def get_xrefs_to(self, ea_or_name):
        """Get code and data cross-references to the target address."""
        if not IDA_AVAILABLE:
            return []
        
        ea = resolve_ea(ea_or_name)
        if ea == ida_idaapi.BADADDR:
            return []
        
        xrefs = []
        for xref in idautils.XrefsTo(ea):
            func_name = ida_funcs.get_func_name(xref.frm) or ""
            xrefs.append({
                "from_ea": hex(xref.frm),
                "type": xref.type,
                "is_code": bool(xref.iscode),
                "func_name": func_name
            })
        return xrefs

    def rename_symbol(self, ea_or_name, new_name):
        """Rename function or variable at given address."""
        if not IDA_AVAILABLE:
            return {"error": "IDA Pro environment not available."}
        
        ea = resolve_ea(ea_or_name)
        if ea == ida_idaapi.BADADDR:
            return {"error": f"Symbol or address '{ea_or_name}' not found."}
        
        success = ida_name.set_name(ea, str(new_name), ida_name.SN_CHECK)
        return {
            "status": "ok" if success else "failed",
            "ea": hex(ea),
            "new_name": new_name
        }

    def get_bytes(self, ea_or_name, length=64):
        """Read raw bytes from specified address."""
        if not IDA_AVAILABLE:
            return {"error": "IDA Pro environment not available."}
        ea = resolve_ea(ea_or_name)
        if ea == ida_idaapi.BADADDR:
            return {"error": f"Address '{ea_or_name}' not found."}
        length = min(max(1, int(length)), 4096)
        raw_bytes = ida_bytes.get_bytes(ea, length)
        if raw_bytes is None:
            return {"error": f"Failed to read {length} bytes at {hex(ea)}."}
        return {
            "status": "ok",
            "ea": hex(ea),
            "length": len(raw_bytes),
            "hex": raw_bytes.hex(),
            "ascii": repr(raw_bytes)[2:-1]
        }

    def py_eval(self, code_str):
        """Execute arbitrary IDAPython expression or snippet safely."""
        if not IDA_AVAILABLE:
            return {"error": "IDA Pro environment not available."}
        try:
            import io
            from contextlib import redirect_stdout
            stdout_buf = io.StringIO()
            res = None
            with redirect_stdout(stdout_buf):
                try:
                    res = eval(code_str, globals(), locals())
                except SyntaxError:
                    exec(code_str, globals(), locals())
            captured = stdout_buf.getvalue().strip()
            return {
                "status": "ok",
                "result": str(res) if res is not None else captured,
                "stdout": captured
            }
        except Exception as e:
            return {"error": f"Execution error: {str(e)}"}

class ReusableSimpleXMLRPCServer(SimpleXMLRPCServer):
    allow_reuse_address = True

def start_rpc_server():
    print(f"[*] Waiting for IDA auto-analysis to complete on '{ida_nalt.get_root_filename()}'...")
    ida_auto.auto_wait()
    print("[✓] Auto-analysis completed.")

    service = IDARpcService()
    server = ReusableSimpleXMLRPCServer(("127.0.0.1", PORT), allow_none=True, logRequests=False)
    server.register_instance(service)
    
    print(f"================================================================")
    print(f"🚀 IDA Pro 9.0 Hex-Rays XML-RPC Daemon listening on 127.0.0.1:{PORT}")
    print(f"👉 Target File : {service.root_file}")
    print(f"👉 Hex-Rays    : {'Active' if service.hexrays_initialized else 'Disabled'}")
    print(f"================================================================")
    sys.stdout.flush()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("[*] Shutting down IDA RPC Daemon...")
        ida_idaapi.qexit(0)

if __name__ == "__main__" or "ida_idaapi" in globals():
    start_rpc_server()
