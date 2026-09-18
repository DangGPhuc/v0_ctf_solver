# 🧠 Continuous Self-Evolution Post-Mortem: collector

- **Challenge**: `collector`
- **Category**: `REV`
- **Ingested Playbook**: [z3_inversion_and_dynamic_extraction](../rev/z3_inversion_and_dynamic_extraction.md)
- **Date Ingested**: `2026-09-02`

---

## 1. The Challenge & Blocker
Advanced CTF Challenge solved with breakthrough technical insights.

---

## 2. Breakthrough Solution Code
```python
import z3

MASK = (1<<64)-1
SBOX = [0x0c,0x05,0x06,0x0b,0x09,0x00,0x0a,0x0d,0x03,0x0e,0x0f,0x08,0x04,0x07,0x01,0x02]

def rol64(x, n): return ((x << n) | z3.LShR(x, 64-n))
def ror16(x, n): return ((z3.LShR(x, n)) | (x << (16-n)))
def rol16(x, n): return ((x << n) | (z3.LShR(x, 16-n)))

def cv102(v96, v123):
    x = (v96 ^ v123 ^ 0xA24BAED4963EE407)
    t = x - 0x61C8864680B583EB
    i1 = t ^ z3.LShR(t, 30)
    t2 = 0xBF58476D1CE4E5B9 * i1
    t3 = t2 ^ z3.LShR(t2, 27)
    t4 = 0x94D049BB133111EB * t3
    return t4 ^ z3.LShR(t4, 31)

def sbox_expr(x):
    # build if-then-else for SBOX
    expr = z3.BitVecVal(SBOX[0], 64)
    for i in range(1, 16):
        expr = z3.If(x == i, z3.BitVecVal(SBOX[i], 64), expr)
    return expr

def nibble_perm(x):
    res = z3.BitVecVal(0, 64)
    for i in range(16):
        nib = z3.Extract(4*i+3, 4*i, x)
        nib64 = z3.ZeroExt(60, nib)
        mapped = sbox_expr(nib64)
        res |= (mapped << (4*i))
    return res

def bit_shuf(v100):
    v106 = z3.BitVecVal(0, 64)
    for i in range(63):
        bit = z3.Extract(i, i, v100)
        bit64 = z3.ZeroExt(63, bit)
        v106 |= (bit64 << ((16*i)%63))
    v99 = v106 | (v100 & 0x8000000000000000)
    return v99, v106

# Solve for v99_init
s = z3.Solver()
v99_init = z3.BitVec('v99_init', 64)

v138_final = z3.BitVecVal(4137310627032430082, 64)
v96 = z3.BitVecVal(0x9E3779B97F4A7C15, 64)
v99 = v99_init

expected_obs = [28342, 26590, 14799, 26263, 27497, 3524]

for i in range(3):
    v102 = cv102(v96, v138_final)
    v103 = v102 ^ v99
    v100 = nibble_perm(v103)
    v99, v106 = bit_shuf(v100)
    
    hi99 = z3.Extract(63, 48, v99)
    w1106 = z3.Extract(31, 16, v106)
    w299 = z3.Extract(47, 32, v99)
    lo102 = z3.Extract(15, 0, v102)
    lo106 = z3.Extract(15, 0, v106)
    w1102 = z3.Extract(31, 16, v102)
    
    oa = ror16(hi99, 5) ^ rol16(w1106, 1) ^ lo102 ^ lo106 ^ rol16(w299, 5)
    ob = w1106 ^ rol16(lo106, 2) ^ w1102 ^ ror16(w299, 7) ^ ror16(hi99, 3)
    
    s.add(oa == expected_obs[2*i])
    s.add(ob == expected_obs[2*i+1])
    
    v96 -= 0x61C8864680B583EB

print("Solving for v99_init...")
if s.check() == z3.sat:
    m = s.model()
    v99_val = m[v99_init].as_long()
    print(f"Found v99_init = {hex(v99_val)}")
    
    # Now invert v99 to find mix (and thus groups)
    v138_f = 4137310627032430082
    x2 = (v138_f ^ 0x43C6EF372FE94D81) & MASK
    t = (x2 - 0x61C8864680B583EB) & MASK
    i2 = (t ^ (t >> 30)) & MASK
    t4 = (0xBF58476D1CE4E5B9 * i2) & MASK
    t5 = (t4 ^ (t4 >> 27)) & MASK
    v98 = (0x94D049BB133111EB * t5) & MASK
    
    mix = v99_val ^ v98 ^ (v98 >> 31)
    
    g0 = mix & 0xFFFF
    g1 = (mix >> 16) & 0xFFFF
    g2 = (mix >> 32) & 0xFFFF
    g3 = (mix >> 48) & 0xFFFF
    
    cand = f"e{g0:04x}{g1:04x}{g2:04x}{g3:04x}"
    print(f"Candidate: {cand}")
else:
    print("UNSAT")
print(f"FLAG{{{cand}}}")

```
