# Cryptography Operational Triage

## 1. Cryptosystem Classification
- Public Key (RSA): Small e (Coppersmith, Hastad), common modulus, Wiener / Boneh-Durfee (small d), factorable N.
- Elliptic Curves (ECC): Invalid curve, small subgroup, singular curve, Smart attack (p = q), ECDSA nonce reuse/bias.
- Lattices / LWE: Knapsack/subset sum, Hidden Number Problem (HNP), Learning With Errors (LWE), Babai CVP.
- Symmetric Ciphers: AES CBC padding oracle, bit-flipping, ECB block rearrangement, GCM nonce reuse.
- PRNG: MT19937 state recovery (randcrack), Linear Congruential Generator (LCG).

## 2. Parameter Inspection
- Extract modulus bits, exponent sizes, curve equations, IVs, nonces, and ciphertexts.
