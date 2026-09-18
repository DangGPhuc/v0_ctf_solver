# Lattice Attacks & LLL Reduction (skills/crypto/lattice-attacks.md)

## 1. Core Concepts: LLL & CVP

- **Lenstra–Lenstra–Lovász (LLL)**: Finds short, nearly orthogonal basis vectors in polynomial time.
- **Closest Vector Problem (CVP) / Babai's Nearest Plane**: Given target vector $\mathbf{t}$ and lattice $\mathcal{L}$, finds lattice point $\mathbf{v} \in \mathcal{L}$ close to $\mathbf{t}$.

---

## 2. Hidden Number Problem (HNP) & ECDSA Nonce Bias

When $k$ (the ECDSA nonce) leaks $l$ MSBs or LSBs across $m$ signatures $(r_i, s_i)$:
$$k_i = 2^l \cdot k_{\text{high}, i} + k_{\text{low}, i}$$
$$s_i \cdot k_i \equiv h_i + r_i \cdot d \pmod q$$

### SageMath Lattice Construction:
```python
# SageMath
def solve_hnp(signatures, q, l_leak):
    """
    Solves HNP using Kannan's embedding technique.
    signatures: list of tuples (r, s, hash_val, nonce_msb)
    """
    m = len(signatures)
    B = 2^(256 - l_leak) # Bound on unknown nonce part
    
    matrix_rows = []
    for i in range(m):
        row = [0] * (m + 2)
        row[i] = q
        matrix_rows.append(row)
        
    row_d = []
    row_const = []
    for r, s, h, msb in signatures:
        t_i = (r * inverse_mod(s, q)) % q
        u_i = ((msb - h) * inverse_mod(s, q)) % q
        row_d.append(t_i)
        row_const.append(u_i)
        
    matrix_rows.append(row_d + [B / q, 0])
    matrix_rows.append(row_const + [0, B])
    
    L = Matrix(QQ, matrix_rows)
    L_reduced = L.LLL()
    
    for row in L_reduced:
        if row[-1] == B or row[-1] == -B:
            # Reconstruct private key d
            print("[+] Found potential candidate row!")
            return row
```

---

## 3. Merkle-Hellman Knapsack via LLL (Lagarias-Odlyzko)
Given public weights $\mathbf{a} = [a_1, a_2, \dots, a_n]$ and sum $S = \sum b_i a_i$:

```python
# SageMath
n = len(a)
M = Matrix(ZZ, n + 1, n + 1)
for i in range(n):
    M[i, i] = 1
    M[i, n] = a[i] * 2
M[n, n] = S * 2

# Scale identity row
for i in range(n):
    M[n, i] = 1

L = M.LLL()
for row in L:
    # Check if row elements are in {-1, 1} or {0, 1}
    # Reconstruct bits b_i
    pass
```
