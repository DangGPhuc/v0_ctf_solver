# Elliptic Curve Cryptography Attacks (skills/crypto/ecc-attacks.md)

## 1. ECDSA Nonce Reuse Attack

If two signatures $(r_1, s_1)$ and $(r_2, s_2)$ share the same nonce $k$ ($r_1 = r_2$):
$$k = \frac{h_1 - h_2}{s_1 - s_2} \pmod q$$
$$d = \frac{s_1 \cdot k - h_1}{r_1} \pmod q$$

### Python Solution:
```python
from gmpy2 import invert

def ecdsa_nonce_reuse(h1, s1, r1, h2, s2, q):
    k = ((h1 - h2) * invert(s1 - s2, q)) % q
    d = ((s1 * k - h1) * invert(r1, q)) % q
    return d
```

---

## 2. Smart's Attack on Anomalous Curves ($\#E(\mathbb{F}_p) = p$)
When the order of the curve equals the field characteristic ($\#E = p$), the discrete logarithm problem can be solved in $O(1)$ time via $p$-adic lift:

```python
# SageMath
def smart_attack(P, Q):
    E = P.curve()
    p = E.base_ring().order()
    
    # Lift curve to p-adic field Qp
    # Compute p-adic formal logarithm
    # d = log_p(Q) / log_p(P) mod p
    # ...
```

---

## 3. Invalid Curve Attacks
If an implementation receives a public point $(x, y)$ and fails to verify that $y^2 \equiv x^3 + ax + b \pmod p$:
- Send points on a curve with low order: $y^2 \equiv x^3 + ax + b' \pmod p$.
- Recover $d \pmod{\text{order}_i}$ and combine via Chinese Remainder Theorem (CRT).
