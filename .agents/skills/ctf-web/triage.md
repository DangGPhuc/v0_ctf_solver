# Web Exploitation Operational Triage

## 1. Attack Surface Enumeration
- HTTP Methods & Routes: GET, POST, PUT, DELETE endpoints from source, robots.txt, sitemap.
- Authentication: JWT, session cookies, OAuth, HTTP basic auth.
- Input Sinks: Query parameters, POST bodies (JSON, XML, form-data), headers (Host, User-Agent, X-Forwarded-For).

## 2. Technology Stack Fingerprint
- Backend runtime: Python (Flask, Django, FastAPI), Node.js (Express), PHP, Java (Spring), Go.
- Database: SQLite, PostgreSQL, MySQL, MongoDB, Redis.
- Caching / Reverse Proxy: Nginx, Cloudflare, Apache, Varnish.
