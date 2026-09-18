# Deep Dive: High-Dimension Lattice Reduction ($n > 100$) & BKZ

## 1. BKZ (Block Korkine-Zolotarev) vs LLL
- Standard LLL runs in polynomial time $O(d^5 \cdot B)$ but is only effective for lattice dimensions $d \le 60 - 80$.
- For dimensions $d > 80$, LLL fails to find the shortest non-zero vector (SVP).
- **Solution**: Use BKZ with block size $\beta \in [10, 40]$ or fplll (`BKZ2.0`).

---

## 2. SageMath / fplll Implementation

```python
from sage.all import *
from fpylll import IntegerMatrix, BKZ, LLL

def reduce_high_dim_lattice(matrix_rows, block_size=20):
    """
    matrix_rows: list of integer lists representing the lattice basis
    """
    dim = len(matrix_rows)
    print(f"[*] Lattice Dimension: {dim}. Starting BKZ reduction (block_size={block_size})...")
    
    A = IntegerMatrix.from_matrix(matrix_rows)
    # Step 1: Fast LLL pre-reduction
    LLL.reduction(A)
    # Step 2: BKZ block reduction
    BKZ.reduction(A, BKZ.Param(block_size=block_size))
    
    reduced_matrix = Matrix(ZZ, [list(row) for row in A])
    shortest_vector = reduced_matrix[0]
    print(f"[+] Shortest Vector Norm: {shortest_vector.norm():.2f}")
    return reduced_matrix
```

---

## 3. Hidden Number Problem (HNP) under ECDSA Nonce Leaks
- When given $m$ signatures $(r_i, s_i, h_i)$ where nonce $k_i \equiv s_i^{-1}(h_i + r_i d) \pmod q$ has $l$ known MSBs/LSBs:
- Construct Kannan's embedding matrix of dimension $(m+1) \times (m+1)$:
  $$M = \begin{pmatrix} q & 0 & \dots & 0 & 0 \\ 0 & q & \dots & 0 & 0 \\ \vdots & \vdots & \ddots & \vdots & \vdots \\ t_1 & t_2 & \dots & t_m & 2^{-l} \\ u_1 & u_2 & \dots & u_m & 0 \end{pmatrix}$$
- Run BKZ to extract private key $d$.
