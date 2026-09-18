# Deep Dive: Adaptive Rate-Limiting, Exponential Backoff & WAF Anti-Ban

## 1. Threat & Problem Overview
Tier-1 CTF Web challenges (Google CTF, Real World CTF, DEF CON) employ aggressive rate-limiters (Nginx `limit_req_zone`, Cloudflare, AWS WAF, custom token buckets).
AI agents sending naive synchronous loops or high-concurrency brute forces will instantly trigger **HTTP 429 Too Many Requests**, TCP RST drops, or temporary IP bans.

---

## 2. Architecture of Adaptive Rate-Limiting Solver

### A. Full Async Worker with Token Bucket & Exponential Backoff
```python
import asyncio
import httpx
import time
import json
from pathlib import Path

STATE_FILE = Path("state.json")

class AdaptiveRequester:
    def __init__(self, base_delay: float = 0.05, max_retries: int = 5, concurrency: int = 5):
        self.delay = base_delay
        self.max_retries = max_retries
        self.semaphore = asyncio.Semaphore(concurrency)
        self.session = httpx.AsyncClient(verify=False, timeout=10.0, limits=httpx.Limits(max_keepalive_connections=20))

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        async with self.semaphore:
            current_backoff = 1.0
            for attempt in range(self.max_retries):
                try:
                    await asyncio.sleep(self.delay)
                    resp = await self.session.request(method, url, **kwargs)
                    
                    # Check for rate limit indicators
                    if resp.status_code == 429 or "rate limit" in resp.text.lower():
                        retry_after = float(resp.headers.get("Retry-After", current_backoff))
                        print(f"[!] Rate-limited (429). Exponential backoff: sleeping {retry_after:.2f}s...")
                        await asyncio.sleep(retry_after)
                        self.delay = min(self.delay * 1.5, 2.0) # Adaptive throttle increase
                        current_backoff *= 2.0
                        continue
                    
                    # On successful request, slowly relax delay
                    if self.delay > 0.05:
                        self.delay = max(0.05, self.delay * 0.95)
                    return resp

                except (httpx.ConnectError, httpx.TimeoutException) as e:
                    print(f"[!] Connection warning: {e}. Backing off {current_backoff:.2f}s...")
                    await asyncio.sleep(current_backoff)
                    current_backoff *= 2.0

            raise RuntimeError(f"Exceeded max retries on {url}")

    async def close(self):
        await self.session.aclose()
```

---

## 3. Persistent Checkpointing (`state.json`)
Never lose progress during multi-hour blind injections or token brute-forces.

```python
def load_checkpoint() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {"recovered_flag": "FLAG{", "tested_indices": []}

def save_checkpoint(data: dict):
    STATE_FILE.write_text(json.dumps(data, indent=2))
```
