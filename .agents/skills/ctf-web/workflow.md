# Web Exploitation Operational Workflow

1. Mapping: Enumerate accessible routes, parameters, and application state.
2. Vulnerability Probing:
   - Injection: SQLi (union, blind), SSTI, Command Injection.
   - Access Control: IDOR, parameter pollution, broken object level authorization.
   - Server-Side: SSRF, path traversal, file upload, insecure deserialization.
   - Client-Side: XSS, CSRF, DOM race conditions.
3. Exploit Delivery: Construct payload to extract database contents, files (/flag, /etc/passwd), or execute commands.
4. Flag Exfiltration: Retrieve flag from response body, out-of-band server, or leaked database table.
