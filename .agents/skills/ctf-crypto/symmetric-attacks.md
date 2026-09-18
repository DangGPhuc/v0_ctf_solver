# Symmetric Ciphers & AES Attacks (skills/crypto/symmetric-attacks.md)

## 1. AES CBC Padding Oracle Attack

Decrypt byte-by-byte from right to left using PKCS#7 padding validation oracle:

```python
def padding_oracle_decrypt_block(oracle_fn, prev_block, curr_block, block_size=16):
    """
    oracle_fn(iv + block) -> returns True if padding is valid, False otherwise.
    """
    decrypted_block = bytearray(block_size)
    intermediate = bytearray(block_size)
    
    for i in range(1, block_size + 1):
        target_pos = block_size - i
        for guess in range(256):
            craft_iv = bytearray(block_size)
            # Set suffix bytes to target padding value i
            for j in range(block_size - 1, target_pos, -1):
                craft_iv[j] = intermediate[j] ^ i
            craft_iv[target_pos] = guess
            
            if oracle_fn(bytes(craft_iv) + curr_block):
                intermediate[target_pos] = guess ^ i
                decrypted_block[target_pos] = intermediate[target_pos] ^ prev_block[target_pos]
                break
                
    return bytes(decrypted_block)
```

---

## 2. AES-ECB Byte-at-a-Time Chosen Plaintext Attack

When oracle encrypts $\text{AES-ECB}(\text{User\_Input} + \text{Secret\_Flag})$:
1. Determine block size (usually 16 bytes).
2. Send $15, 14, \dots, 0$ pad bytes (`b'A' * (15 - i)`).
3. Brute-force byte $i$ by matching ciphertext block outputs against dictionary of all 256 possible bytes.

---

## 3. AES-GCM Nonce Reuse (Forbidden Attack)
When same $(K, IV)$ is used twice:
- Recover authentication key $H = \text{AES}_K(0)$.
- Compute GHASH difference $T_1 - T_2$ as a polynomial over $\mathbb{F}_{2^{128}}$.
- Forge valid auth tags for any arbitrary ciphertext.
