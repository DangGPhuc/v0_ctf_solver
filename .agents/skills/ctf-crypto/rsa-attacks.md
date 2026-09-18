# RSA Attacks Playbook (skills/crypto/rsa-attacks.md)

## 1. Fast Triage Matrix

| Condition / Vulnerability | Attack Name | Tool / Method |
| :--- | :--- | :--- |
| Small $e$ (e.g. $e=3$) & unpadded $m$ | Small Exponent Attack | $m = \text{integer\_nth\_root}(c, e)$ |
| Small $d$ ($d < \frac{1}{3} N^{0.25}$) | Wiener's Attack | Continued fractions of $e/N$ |
| Moderate $d$ ($d < N^{0.292}$) | Boneh-Durfee Attack | Lattice small roots (SageMath) |
| Known high/low bits of $p$ | Coppersmith Factorization | `f = x + p_known; f.small_roots()` |
| Same message sent to multiple moduli | Hastad's Broadcast | Chinese Remainder Theorem (CRT) |
| Related messages $m_1, m_2 = a \cdot m_1 + b$ | Franklin-Reiter Attack | $\gcd(f_1(x), f_2(x)) \pmod N$ |
| Common Modulus $N$ with $\gcd(e_1, e_2) = 1$| Common Modulus Attack | Extended Euclidean: $e_1 u + e_2 v = 1 \implies c_1^u c_2^v \pmod N$ |
| Small difference $|p - q| < N^{0.25}$ | Fermat's Factorization | $a = \lceil\sqrt{N}\rceil$; test $a^2 - N = b^2$ |

---

## 2. SageMath Implementations

### 2.1 Coppersmith Factorization (Known High Bits of $p$)
```python
# SageMath Script
N = ...
p_known_bits = ... # high bits shifted to correct position
kbits = 512 # total bit length of p
unknown_bits = 100 # number of low unknown bits

PR.<x> = PolynomialRing(Zmod(N))
f = x + p_known_bits
roots = f.small_roots(X=2^unknown_bits, beta=0.4)
if roots:
    p = p_known_bits + int(roots[0])
    q = N // p
    print(f"[+] Found p = {p}, q = {q}")
```

### 2.2 Wiener's Attack (SageMath / Python)
```python
import owiener # pip install owiener
d = owiener.attack(e, N)
if d:
    m = pow(c, d, N)
    print(f"[+] Decrypted: {bytes.fromhex(hex(m)[2:])}")
```
