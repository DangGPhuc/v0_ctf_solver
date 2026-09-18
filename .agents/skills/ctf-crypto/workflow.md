# Cryptography Operational Workflow

1. Model Formulation: Formulate mathematical equations representing encryption / signature verification.
2. Weakness Identification: Identify algebraic shortcuts, dimension reduction bounds, or nonce collisions.
3. Attack Implementation:
   - Implement lattice reduction (LLL / BKZ) or polynomial roots in SageMath.
   - Implement bit-flipping or padding oracle in Python.
4. Key / Plaintext Recovery: Solve for private key, trapdoor, or decrypt flag ciphertext.
5. Verification: Decrypt target ciphertext and verify flag prefix.
