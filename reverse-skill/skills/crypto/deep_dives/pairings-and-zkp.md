# Deep Dive: Elliptic Curve Pairings & Zero-Knowledge Proof (ZKP) Flaws

## 1. Bilinear Pairings Fundamentals
- A pairing is a non-degenerate, bilinear map $e: \mathbb{G}_1 \times \mathbb{G}_2 \to \mathbb{G}_T$ satisfying:
  $$e(aP, bQ) = e(P, Q)^{ab} = e(bP, aQ)$$
- Standard Curves: BLS12-381, BN254 (alt_bn128).

---

## 2. Common CTF Vulnerability Primitives

### A. Under-Constrained Polynomials in Circom / R1CS (ZKP)
- In Zero-Knowledge circuits (Groth16, PLONK), a developer might forget to constrain an intermediate signal:
  ```circom
  signal input a;
  signal input b;
  signal output c;
  c <-- a / b; // Assignment only WITHOUT constraint! Missing: c * b === a;
  ```
- **Exploit**: The prover can supply an arbitrary output $c$ and generate a mathematically valid proof because $b \cdot c$ is never asserted to equal $a$.

### B. Degenerate Pairing / Small Subgroup Attack
- If point $P \in \mathbb{G}_1$ or $Q \in \mathbb{G}_2$ is not checked for membership in the correct $r$-order subgroup:
  - Feeding a low-order point yields $e(P, Q) = 1$ in $\mathbb{G}_T$, trivializing signature verification or zero-knowledge opening checks.
