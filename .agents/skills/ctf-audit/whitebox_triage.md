# Whitebox Source Code Triage Playbook (skills/audit/whitebox_triage.md)

## 1. Source-to-Sink Mental Model
Every whitebox vulnerability follows a strict data-flow chain:
`Untrusted Source` $\longrightarrow$ `[Optional Sanitizer/Validator]` $\longrightarrow$ `Dangerous Sink`

```text
[HTTP Input / User Data] 
       │
       ▼ (Check: Is it sanitized, type-cast, or regex-validated?)
[Sanitizer / Filter] ──(Bypassable? Type confusion? Logic flaw?)──► [Dangerous Sink]
                                                                          │
                                                                          ▼
                                                                [Exploit / Flag Leak]
```

---

## 2. Language-Specific Sink & Source Registry

| Language | Untrusted Sources | Dangerous Sinks | Vulnerability Class |
| :--- | :--- | :--- | :--- |
| **Python** | `request.args`, `request.form`, `request.json`, `request.cookies` | `pickle.loads()`, `yaml.load()`, `eval()`, `exec()`, `os.system()`, `subprocess.Popen()`, `render_template_string()` | Deserialization, RCE, SSTI |
| **Node.js** | `req.query`, `req.body`, `req.headers`, `req.params` | `eval()`, `Function()`, `child_process.exec()`, `vm.runInContext()`, recursive `merge()/clone()`, `res.render()` | Code Injection, Command Injection, Prototype Pollution |
| **PHP** | `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_SERVER` | `eval()`, `assert()`, `system()`, `exec()`, `unserialize()`, `include/require`, `preg_replace('/e')`, `file_get_contents()` | RCE, Deserialization, LFI/RFI, SSRF |
| **Java** | `@RequestParam`, `@RequestBody`, `@PathVariable`, `HttpServletRequest` | `ObjectInputStream.readObject()`, `Runtime.getRuntime().exec()`, `ProcessBuilder`, `EntityManager.createQuery()` | Deserialization, Command Injection, SQLi, SpEL Injection |
| **Go** | `c.Query()`, `r.URL.Query()`, `r.Body` | `os/exec.Command()`, `template.HTML()`, `sql.DB.Query(fmt.Sprintf)` | Command Injection, XSS, SQLi |

---

## 3. Fast Static Triage Checklist (Step-by-Step)

1. **Map Entry Points & Routing**:
   - Grep all route definitions (`@app.route`, `router.get`, `app.post`, `Route::`).
   - Identify unauthenticated vs authenticated routes.
2. **Backward Slice from Sinks (Sink-to-Source)**:
   - Grep for highest-impact sinks (`exec`, `eval`, `system`, `unserialize`, `pickle`, `render`).
   - Trace back parameters to check if user controls arguments.
3. **Analyze Sanitizers & Validators**:
   - Check for regex flaws (missing anchors `^...$`, multi-line mode bypasses).
   - Check for loose type equality (PHP `==`, JavaScript `==`).
   - Check for blacklist vs whitelist filtering (Blacklists are almost always bypassable).
4. **Identify Business Logic & State Machines**:
   - Look for state transitions without atomic locks (Race Conditions).
   - Look for parameter tampering / IDOR / privilege flag injection in user profile updates.

---

## 4. Whitebox Grep Cheat Sheet

```bash
# Python Sinks
grep -rnE "(pickle\.loads|yaml\.unsafe_load|eval\(|exec\(|subprocess|os\.system|render_template_string)" ./

# Node.js Sinks
grep -rnE "(child_process|exec\(|spawn\(|eval\(|vm\.runIn|Object\.assign|merge\(|clone\()" ./

# PHP Sinks
grep -rnE "(unserialize|eval\(|system\(|passthru\(|shell_exec\(|include\(|require\(|\$_GET|\$_POST)" ./
```
