---
name: ctf-crypto
description: |
  CTF Cryptography Playbook Suite.
  Covers Lattice-based attacks (LLL, Babai, HNP, CVP), RSA factorization & polynomial small roots (Wiener, Boneh-Durfee, Coppersmith),
  Elliptic Curve Cryptography (ECDSA nonce reuse/bias, invalid curves, Smart's attack), PRNG state recovery (MT19937 randcrack, LCG),
  and Symmetric Cipher attacks (AES CBC padding oracle, bit-flipping, GCM nonce reuse).
---

# CTF Cryptography Suite

## Primary Tooling
- **SageMath**: Run with `sage solve.sage` or `sage -python solve.py`.
- **Pwntools**: Use for interactive network crypto oracles.

## Playbooks in this Module
- [rsa-attacks.md](v0_ctf_knowledge/references/crypto/rsa-attacks.md): Wiener, Boneh-Durfee, Franklin-Reiter, Hastad, Coppersmith small roots.
- [lattice-attacks.md](v0_ctf_knowledge/references/crypto/lattice-attacks.md): LLL matrix construction, Babai Closest Vector, Hidden Number Problem (HNP), Knapsack.
- [ecc-attacks.md](v0_ctf_knowledge/references/crypto/ecc-attacks.md): Nonce reuse/bias, invalid curve attacks, Pollard rho, MOV reduction, Smart's attack.
- [prng-attacks.md](v0_ctf_knowledge/references/crypto/prng-attacks.md): MT19937 untemper & clone via `randcrack`, LCG algebraic recovery.
- [symmetric-attacks.md](v0_ctf_knowledge/references/crypto/symmetric-attacks.md): AES CBC padding oracle, ECB byte-at-a-time, CBC bit-flipping, GCM nonce reuse.
- [dlp-and-math.md](v0_ctf_knowledge/references/crypto/dlp-and-math.md): Discrete Logarithm Problem (BSGS, Pohlig-Hellman), advanced integer factorization.
