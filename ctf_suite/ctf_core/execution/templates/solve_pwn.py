#!/usr/bin/env python3
"""
Standard CTF PWN Solve Template
Usage:
  python3 solve.py --local
  python3 solve.py --remote <host> <port>
  python3 solve.py --gdb
"""

import sys
import argparse
from pwn import *

# ==============================================================================
# CONFIGURATION & BINARY SETUP
# ==============================================================================
BINARY_PATH = './vuln'
LIBC_PATH = './libc.so.6'

elf = ELF(BINARY_PATH, checksec=False)
context.binary = elf
context.log_level = 'info'
context.terminal = ['tmux', 'splitw', '-h'] # or ['gnome-terminal', '--']

libc = ELF(LIBC_PATH, checksec=False) if os.path.exists(LIBC_PATH) else None

# ==============================================================================
# GDB SCRIPT BREAKPOINTS
# ==============================================================================
GDBSCRIPT = """
set follow-fork-mode parent
# b *main
# b *vuln
c
"""

def get_target():
    parser = argparse.ArgumentParser(description="CTF Pwn Exploit Launcher")
    parser.add_argument("--local", action="store_true", help="Run against local binary")
    parser.add_argument("--remote", nargs=2, metavar=("HOST", "PORT"), help="Run against remote target")
    parser.add_argument("--gdb", action="store_true", help="Debug local binary with GDB")
    args = parser.parse_args()

    if args.remote:
        host, port = args.remote[0], int(args.remote[1])
        return remote(host, port)
    elif args.gdb:
        return gdb.debug([elf.path], gdbscript=GDBSCRIPT)
    else:
        return process([elf.path])

# ==============================================================================
# HELPER SHORTCUTS & SAFE-LINKING
# ==============================================================================
def protect_ptr(pos, target):
    """Safe-linking pointer encoding for Glibc >= 2.32."""
    return (pos >> 12) ^ target

def reveal_ptr(mangled):
    """Safe-linking pointer decoding for Glibc >= 2.32."""
    mask = 0xfff << 36
    while mask:
        mangled ^= (mangled & mask) >> 12
        mask >>= 12
    return mangled

# ==============================================================================
# EXPLOIT LOGIC
# ==============================================================================
def main():
    io = get_target()

    # --- Step 1: Leaking Addresses ---
    # io.sendlineafter(b"> ", b"1")
    # leaked = u64(io.recvline().strip().ljust(8, b'\x00'))
    # if libc:
    #     libc.address = leaked - libc.sym['puts']
    #     log.success(f"Libc Base: {hex(libc.address)}")

    # --- Step 2: Payload Construction ---
    # payload = flat({
    #     offset: [
    #         ret_gadget, # 16-byte stack alignment
    #         pop_rdi_ret,
    #         next(libc.search(b'/bin/sh\x00')),
    #         libc.sym['system']
    #     ]
    # })
    # io.sendlineafter(b"> ", payload)

    # --- Step 3: Interactive Shell ---
    io.interactive()

if __name__ == "__main__":
    main()
