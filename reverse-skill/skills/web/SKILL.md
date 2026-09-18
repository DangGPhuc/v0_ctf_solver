---
name: ctf-web
description: |
  CTF Web Exploitation Playbook Suite.
  Covers high-speed async blind SQLi, Server-Side Template Injection (SSTI), JWT/OAuth vulnerabilities,
  Node.js Prototype Pollution, Insecure Deserialization (Python/PHP/Java), Race Conditions, Type Juggling, SSRF, and GraphQL security.
---

# CTF Web Exploitation Suite

## Primary Tooling
- **Python `httpx` / `aiohttp` / `requests`**: High-concurrency requests and binary search.
- **Solve Template**: `templates/solve_web.py`.

## Playbooks in this Module
- [sqli-injection.md](file:///home/kali/reverse-skill/skills/web/sqli-injection.md): Blind Boolean & Time-based binary search, Error-based, Union, NoSQL injection.
- [ssti-payloads.md](file:///home/kali/reverse-skill/skills/web/ssti-payloads.md): Jinja2, Twig, Thymeleaf, Spring SpEL, Mako, Smarty, Freemarker RCE payloads and filter bypasses.
- [auth-jwt-oauth.md](file:///home/kali/reverse-skill/skills/web/auth-jwt-oauth.md): `alg: none`, HMAC-RSA public key confusion, `kid` injection, JKU spoofing.
- [prototype-pollution.md](file:///home/kali/reverse-skill/skills/web/prototype-pollution.md): Node.js server-side gadgets to RCE, client-side DOM XSS.
- [deserialization.md](file:///home/kali/reverse-skill/skills/web/deserialization.md): Python pickle/yaml, PHP object injection & phar wrappers, Java ysoserial.
- [race-conditions.md](file:///home/kali/reverse-skill/skills/web/race-conditions.md): Concurrency TOCTOU, limit-overrun, async parallel solvers.
- [type-juggling.md](file:///home/kali/reverse-skill/skills/web/type-juggling.md): PHP loose comparison (`0e...`, `strcmp`), JSON type confusion, NoSQL BSON operators.
- [ssrf-attacks.md](file:///home/kali/reverse-skill/skills/web/ssrf-attacks.md): Cloud metadata, DNS rebinding, URL parser bypasses, Gopher smuggling.
- [graphql-attacks.md](file:///home/kali/reverse-skill/skills/web/graphql-attacks.md): Schema introspection dump, alias batching, depth limits.
