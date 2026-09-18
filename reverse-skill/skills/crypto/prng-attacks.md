# PRNG Attacks Playbook (skills/crypto/prng-attacks.md)

## 1. Mersenne Twister (MT19937) Reconstruction via `randcrack`

Given 624 continuous 32-bit outputs from Python's standard `random` module:

```python
from randcrack import RandCrack
import random

rc = RandCrack()

# Feed 624 observed integers (32-bit)
for val in leaked_624_integers:
    rc.submit(val)

# Predict all future random values perfectly
predicted = rc.predict_getrandbits(32)
print(f"[+] Predicted next random: {predicted}")
```

---

## 2. Linear Congruential Generator (LCG) Recovery
Formula: $X_{n+1} = (a \cdot X_n + c) \pmod m$.

If $m$ is known:
$$a = (X_2 - X_3) \cdot (X_1 - X_2)^{-1} \pmod m$$
$$c = (X_2 - a \cdot X_1) \pmod m$$

If $m$ is unknown:
Given consecutive outputs $X_0, X_1, X_2, X_3, X_4, X_5$:
Let $t_n = X_{n+1} - X_n$.
Let $u_n = |t_{n+2} t_n - t_{n+1}^2|$.
Then $m = \gcd(u_1, u_2, u_3, u_4)$.
