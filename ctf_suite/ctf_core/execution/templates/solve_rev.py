#!/usr/bin/env python3
"""
Standard CTF Reverse Engineering Solve Template (Z3 & Angr)
Usage:
  python3 solve_rev.py --z3
  python3 solve_rev.py --angr
"""

import sys
import argparse
from z3 import *

# ==============================================================================
# BITWISE HELPER FUNCTIONS (Prevent Signedness / Shift Mismatches)
# ==============================================================================
def ROR(val, r, bits=32):
    """Right rotate for Z3 BitVectors."""
    return LShR(val, r) | (val << (bits - r))

def ROL(val, r, bits=32):
    """Left rotate for Z3 BitVectors."""
    return (val << r) | LShR(val, bits - r)

# ==============================================================================
# 1. Z3 SMT BITVECTOR SOLVER TEMPLATE
# ==============================================================================
def solve_with_z3():
    print("[*] Running Z3 Solver...")
    FLAG_LEN = 32
    s = Solver()

    # Create 8-bit symbolic variables for each flag character
    flag = [BitVec(f'c_{i}', 8) for i in range(FLAG_LEN)]

    # Constrain to printable ASCII characters
    for c in flag:
        s.add(c >= 0x20, c <= 0x7e)

    # Known prefix & suffix
    known_prefix = b"FLAG{"
    for i, b in enumerate(known_prefix):
        s.add(flag[i] == b)
    s.add(flag[-1] == ord('}'))

    # --- ADD DECOMPILED EQUATIONS HERE ---
    # Example: s.add(flag[0] ^ flag[1] == 0x34)

    if s.check() == sat:
        m = s.model()
        result = bytes([m[c].as_long() for c in flag])
        print(f"[+] SUCCESS! Flag: {result.decode('latin-1')}")
    else:
        print("[-] UNSAT! Check constraints or hypothesis.")

# ==============================================================================
# 2. ANGR SYMBOLIC EXECUTION TEMPLATE
# ==============================================================================
def solve_with_angr():
    print("[*] Running Angr Symbolic Execution...")
    try:
        import angr
        import claripy
    except ImportError:
        print("[-] Angr not installed. Install via: pip install angr")
        return

    BINARY_PATH = './chal'
    FLAG_LEN = 32

    proj = angr.Project(BINARY_PATH, auto_load_libs=False)

    flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(FLAG_LEN)]
    flag_sym = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])

    state = proj.factory.entry_state(
        args=[BINARY_PATH],
        stdin=flag_sym,
        add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY}
    )

    for c in flag_chars:
        state.solver.add(c >= 0x20)
        state.solver.add(c <= 0x7e)

    simgr = proj.factory.simulation_manager(state)

    # Replace with target addresses from IDA Pro
    FIND_ADDR = 0x401234
    AVOID_ADDR = 0x401250

    simgr.explore(find=FIND_ADDR, avoid=AVOID_ADDR)

    if simgr.found:
        found_state = simgr.found[0]
        solved_flag = found_state.solver.eval(flag_sym, cast_to=bytes)
        print(f"[+] Found Flag: {solved_flag}")
    else:
        print("[-] Angr could not find a path to the target address.")

# ==============================================================================
# ENTRY POINT
# ==============================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CTF Rev Solver")
    parser.add_argument("--angr", action="store_true", help="Use Angr engine")
    parser.add_argument("--z3", action="store_true", help="Use Z3 engine (default)")
    args = parser.parse_args()

    if args.angr:
        solve_with_angr()
    else:
        solve_with_z3()
