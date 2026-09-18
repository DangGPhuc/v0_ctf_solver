# Z3 SMT Solver Playbook (skills/rev/z3-solver.md)

## 1. BitVector vs Integer Modeling

- **BitVector (`BitVec('x', 8/32/64)`)**: Use for all bitwise operations (`^`, `&`, `|`, `<<`, `>>`, integer overflow/underflow, rotate).
- **Int (`Int('x')`)**: Use only for pure mathematical equations without bitwise logic.

---

## 2. Standard CTF Flag Checker Model

```python
from z3 import *

FLAG_LEN = 32
s = Solver()

# 1. Create 8-bit symbolic BitVectors for flag characters
flag = [BitVec(f'flag_{i}', 8) for i in range(FLAG_LEN)]

# 2. Constrain to printable ASCII range
for c in flag:
    s.add(c >= 0x20, c <= 0x7e)

# 3. Known Prefix & Suffix Constraints
known_prefix = b"FLAG{"
for i, b in enumerate(known_prefix):
    s.add(flag[i] == b)
s.add(flag[-1] == ord('}'))

# 4. Add Constraints from Decompiled Code
# Example: flag[i] ^ flag[i+1] == target[i]
# Or custom matrix multiplication / substitution
# s.add(...)

# 5. Check Satisfiability and Solve
if s.check() == sat:
    m = s.model()
    solved_flag = bytes([m[c].as_long() for c in flag])
    print(f"[+] Flag: {solved_flag.decode('latin-1')}")
else:
    print("[-] Unsat! Check constraints.")
```

---

## 3. Handling Cyclic Shifts & Arrays in Z3
```python
def ROR(val, r, bits=32):
    return LShR(val, r) | (val << (bits - r))

def ROL(val, r, bits=32):
    return (val << r) | LShR(val, bits - r)
```
