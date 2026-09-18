# Discrete Log & Advanced Math (skills/crypto/dlp-and-math.md)

## 1. Discrete Logarithm Algorithms

Given $g^x \equiv h \pmod p$, find $x$:

### 1.1 Baby-Step Giant-Step (BSGS) - $O(\sqrt{p})$
```python
# SageMath
F = GF(p)
g = F(g)
h = F(h)
x = discrete_log(h, g) # Sage automatically picks the best algorithm
```

### 1.2 Pohlig-Hellman Algorithm (Smooth Order $p-1$)
If $p - 1 = \prod q_i^{e_i}$ where all $q_i$ are small primes:
- Solve DLOG modulo each small prime factor $q_i^{e_i}$.
- Combine results with Chinese Remainder Theorem (CRT).
```python
# SageMath
x = discrete_log(h, g, order=p-1, operation='*')
```

---

## 2. Advanced Integer Factorization

1. **Pollard's $p-1$ Algorithm**: Works when $p-1$ is $B$-smooth.
2. **Williams' $p+1$ Algorithm**: Works when $p+1$ is $B$-smooth.
3. **Quadratic Sieve / General Number Field Sieve (GNFS)**:
   - Use `yafu` or `msieve` for numbers between 60 to 120 digits:
   ```bash
   yafu "factor(N)"
   ```
