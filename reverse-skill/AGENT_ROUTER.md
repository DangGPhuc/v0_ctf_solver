# CTF AI Agent Router (AGENT_ROUTER.md)

This router acts as the primary decision tree for AI agents solving CTF challenges.

---

## 1. Challenge Intake & Fast Triage Flow

```text
[ Input: Archive / Binary / Netcat / URL ]
                    │
                    ▼
       ┌─────────────────────────┐
       │   python3 ctf.py init   │ ──► Unpack, Patch Libc, Detect Category
       └────────────┬────────────┘
                    │
                    ├─► work/<category>/<chal_name>/triage.json (Structured Metadata)
                    ├─► work/<category>/<chal_name>/solve.py   (Auto-interpolated Template)
                    │
                    ▼
       ┌─────────────────────────┐
       │        AI AGENT         │ ──► Reads triage.json -> Executes Category Playbook
       └────────────┬────────────┘
                    │
                    ▼
       ┌─────────────────────────┐
       │   python3 ctf.py test   │ ──► Runs solver -> Validates FLAG{...}
       └────────────┬────────────┘
                    │
                    ▼
       ┌─────────────────────────┐
       │  python3 ctf.py archive │ ──► Sanitizes Blobs -> Saves Field-Journal Entry
       └─────────────────────────┘
```

---

## 2. Category Signature & Decision Table

| Category | File / Target Signatures | Initial Command | Primary Playbook | Base Template |
| :--- | :--- | :--- | :--- | :--- |
| **PWN** | ELF 32/64, libc.so, heap, buffer overflow, format string | `python3 ctf.py init <name> --file <bin>` | `skills/pwn/stack-pwn.md`<br>`skills/pwn/heap-pwn.md` | `templates/solve_pwn.py` |
| **REV** | Stripped ELF, Windows EXE, APK, Bytecode, VM, OLLVM | `python3 ctf.py init <name> --file <bin>` | `skills/rev/z3-solver.md`<br>`skills/rev/ida-mcp-playbook.md` | `templates/solve_rev.py` |
| **CRYPTO** | `n, e, c`, RSA, ECC, Matrix, LLL, PRNG stream | `python3 ctf.py init <name> --file <file>` | `skills/crypto/rsa-attacks.md`<br>`skills/crypto/lattice-attacks.md` | `templates/solve_crypto.sage` |
| **WEB** | HTTP URL, Dockerfile, Flask/Node/PHP/Java app, GraphQL | `python3 ctf.py init <name> --url <url>` | `skills/web/sqli-injection.md`<br>`skills/web/ssti-payloads.md` | `templates/solve_web.py` |
| **FORENSICS**| `.pcap`, `.pcapng`, `.raw`, `.dmp`, `.png`, `.wav`, disk image | `python3 ctf.py init <name> --file <file>` | `skills/forensics/pcap-analysis.md`<br>`skills/forensics/stego-carving.md` | `toolchain/triage.py` |
| **MISC** | PyJail, Restricted Bash, Brainfuck, LLM prompt jailbreak | `python3 ctf.py init <name> --file <file>` | `skills/misc/pyjail-escape.md`<br>`skills/misc/bash-jail.md` | `templates/solve_misc.py` |

---

## 3. Autonomous Execution Protocol

1. **Workspace Initialization**:
   ```bash
   python3 ctf.py init <chal_name> --file <target_file>
   ```

2. **Read Triage Metadata**:
   - Inspect `work/<category>/<chal_name>/triage.json` for security properties, glibc version, symbols, and indicators.

3. **Playbook Execution**:
   - Reference specific guides in `skills/<category>/<playbook>.md`.
   - Adhere to the **3-Strike Rule** (pivot if 3 attempts fail).

4. **Testing & Flag Verification**:
   ```bash
   python3 ctf.py test <chal_name> [--remote]
   ```

5. **Flag Submission & Archival**:
   ```bash
   python3 ctf.py archive <chal_name> --flag "FLAG{...}"
   ```
