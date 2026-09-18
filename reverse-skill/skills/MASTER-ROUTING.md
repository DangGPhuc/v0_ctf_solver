# CTF Master Routing & Triage Matrix (MASTER-ROUTING.md)

This document provides instant mapping from target signatures to playbooks and solve templates.

---

## 1. Quick Category & Signature Routing Table

| File / Service Signature | Category | Triage Command / Grep | Playbook Reference | Solver Template |
| :--- | :--- | :--- | :--- | :--- |
| **Whitebox Source Code (Python, Node, PHP, Go)** | AUDIT | `grep -rnE "(eval\|exec\|system\|render)"` | [skills/audit/whitebox_triage.md](file:///home/kali/reverse-skill/skills/audit/whitebox_triage.md) | [templates/solve_web.py](file:///home/kali/reverse-skill/templates/solve_web.py) |
| **C / Binary Static Audit (`strcpy`, `gets`, `scanf`)** | AUDIT | `grep -rnE "(strcpy\|sprintf\|gets)"` | [skills/audit/binary_audit.md](file:///home/kali/reverse-skill/skills/audit/binary_audit.md) | [templates/solve_pwn.py](file:///home/kali/reverse-skill/templates/solve_pwn.py) |
| **Autonomous ReAct CTF Reasoning Protocol** | AUDIT | Multi-step ReAct verification | [skills/audit/structured_reasoning.md](file:///home/kali/reverse-skill/skills/audit/structured_reasoning.md) | Standard ReAct Loop |
| **ELF 64-bit / 32-bit (NX, Canary, PIE)** | PWN | `checksec --file=<bin>` | [skills/pwn/stack-pwn.md](file:///home/kali/reverse-skill/skills/pwn/stack-pwn.md) | [templates/solve_pwn.py](file:///home/kali/reverse-skill/templates/solve_pwn.py) |
| **Heap allocations (malloc, free, tcache)** | PWN | `pwndbg> heap`, `bins` | [skills/pwn/heap-pwn.md](file:///home/kali/reverse-skill/skills/pwn/heap-pwn.md) | [templates/solve_pwn.py](file:///home/kali/reverse-skill/templates/solve_pwn.py) |
| **Format String (`printf(user_buf)`)** | PWN | `grep -n "printf" / %p test` | [skills/pwn/format-string.md](file:///home/kali/reverse-skill/skills/pwn/format-string.md) | [templates/solve_pwn.py](file:///home/kali/reverse-skill/templates/solve_pwn.py) |
| **Linux Kernel module (`.ko`, bzImage)** | PWN | `gdb vmlinux` / QEMU | [skills/pwn/kernel-pwn.md](file:///home/kali/reverse-skill/skills/pwn/kernel-pwn.md) | [templates/solve_pwn.py](file:///home/kali/reverse-skill/templates/solve_pwn.py) |
| **Stripped ELF / PE Flag Checker** | REV | IDA Pro MCP Decompile | [skills/rev/z3-solver.md](file:///home/kali/reverse-skill/skills/rev/z3-solver.md) | [templates/solve_rev.py](file:///home/kali/reverse-skill/templates/solve_rev.py) |
| **Complex Branching / Path Exploration**| REV | `angr` simulation | [skills/rev/angr-symbolic.md](file:///home/kali/reverse-skill/skills/rev/angr-symbolic.md) | [templates/solve_rev.py](file:///home/kali/reverse-skill/templates/solve_rev.py) |
| **VM / Custom Bytecode Dispatcher** | REV | Disasm loop / opcode map | [skills/rev/vm-reversing.md](file:///home/kali/reverse-skill/skills/rev/vm-reversing.md) | [templates/solve_rev.py](file:///home/kali/reverse-skill/templates/solve_rev.py) |
| **OLLVM Control Flow Flattening** | REV | De-flattening AST script | [skills/rev/deobfuscation.md](file:///home/kali/reverse-skill/skills/rev/deobfuscation.md) | [templates/solve_rev.py](file:///home/kali/reverse-skill/templates/solve_rev.py) |
| **RSA ($n, e, c$, Wiener, Coppersmith)** | CRYPTO | `sage solve.sage` | [skills/crypto/rsa-attacks.md](file:///home/kali/reverse-skill/skills/crypto/rsa-attacks.md) | [templates/solve_crypto.sage](file:///home/kali/reverse-skill/templates/solve_crypto.sage) |
| **Lattice / LLL / HNP / CVP / Knapsack** | CRYPTO | SageMath Matrix LLL | [skills/crypto/lattice-attacks.md](file:///home/kali/reverse-skill/skills/crypto/lattice-attacks.md) | [templates/solve_crypto.sage](file:///home/kali/reverse-skill/templates/solve_crypto.sage) |
| **Elliptic Curve (ECDSA Nonce Bias)** | CRYPTO | Curve parameters check | [skills/crypto/ecc-attacks.md](file:///home/kali/reverse-skill/skills/crypto/ecc-attacks.md) | [templates/solve_crypto.sage](file:///home/kali/reverse-skill/templates/solve_crypto.sage) |
| **PRNG Stream (MT19937 / LCG)** | CRYPTO | `randcrack` / LCG solve | [skills/crypto/prng-attacks.md](file:///home/kali/reverse-skill/skills/crypto/prng-attacks.md) | [templates/solve_crypto.sage](file:///home/kali/reverse-skill/templates/solve_crypto.sage) |
| **AES CBC Padding Oracle / Bitflip** | CRYPTO | `pwntools` oracle script | [skills/crypto/symmetric-attacks.md](file:///home/kali/reverse-skill/skills/crypto/symmetric-attacks.md) | [templates/solve_crypto.sage](file:///home/kali/reverse-skill/templates/solve_crypto.sage) |
| **Insecure Deserialization (`pickle`, `unserialize`, Java)** | WEB | `grep -rnE "(pickle\|yaml\|unserialize)"` | [skills/web/deserialization.md](file:///home/kali/reverse-skill/skills/web/deserialization.md) | [templates/solve_web.py](file:///home/kali/reverse-skill/templates/solve_web.py) |
| **Server-Side Template Injection (`{{7*7}}`, Jinja, Twig)** | WEB | `curl` / `{{7*7}}` probe | [skills/web/ssti-payloads.md](file:///home/kali/reverse-skill/skills/web/ssti-payloads.md) | [templates/solve_web.py](file:///home/kali/reverse-skill/templates/solve_web.py) |
| **JWT / OAuth Key Confusion (`alg:none`, `RS256->HS256`)** | WEB | JWT header inspection | [skills/web/auth-jwt-oauth.md](file:///home/kali/reverse-skill/skills/web/auth-jwt-oauth.md) | [templates/solve_web.py](file:///home/kali/reverse-skill/templates/solve_web.py) |
| **Prototype Pollution (Node.js `__proto__`)** | WEB | `grep -rnE "(merge\|clone\|__proto__)"` | [skills/web/prototype-pollution.md](file:///home/kali/reverse-skill/skills/web/prototype-pollution.md) | [templates/solve_web.py](file:///home/kali/reverse-skill/templates/solve_web.py) |
| **Race Conditions & Concurrency (TOCTOU)** | WEB | Parallel async test | [skills/web/race-conditions.md](file:///home/kali/reverse-skill/skills/web/race-conditions.md) | [templates/solve_web.py](file:///home/kali/reverse-skill/templates/solve_web.py) |
| **Type Juggling & Loose Comparison (`0e...`, `strcmp`)** | WEB | Loose comparison inspection | [skills/web/type-juggling.md](file:///home/kali/reverse-skill/skills/web/type-juggling.md) | [templates/solve_web.py](file:///home/kali/reverse-skill/templates/solve_web.py) |
| **SSRF & Cloud Metadata (`169.254.169.254`, Gopher)** | WEB | URL fetcher inspection | [skills/web/ssrf-attacks.md](file:///home/kali/reverse-skill/skills/web/ssrf-attacks.md) | [templates/solve_web.py](file:///home/kali/reverse-skill/templates/solve_web.py) |
| **GraphQL Security (Introspection / Batching)** | WEB | `/graphql` introspection probe | [skills/web/graphql-attacks.md](file:///home/kali/reverse-skill/skills/web/graphql-attacks.md) | [templates/solve_web.py](file:///home/kali/reverse-skill/templates/solve_web.py) |
| **Web Blind SQLi / Injection** | WEB | `curl` / `httpx` async test | [skills/web/sqli-injection.md](file:///home/kali/reverse-skill/skills/web/sqli-injection.md) | [templates/solve_web.py](file:///home/kali/reverse-skill/templates/solve_web.py) |
| **Packet Capture (`.pcap`, `.pcapng`)** | FORENSICS| `tshark -r <file>` | [skills/forensics/pcap-analysis.md](file:///home/kali/reverse-skill/skills/forensics/pcap-analysis.md) | [toolchain/triage.py](file:///home/kali/reverse-skill/toolchain/triage.py) |
| **Memory Dump (`.raw`, `.dmp`, `.vmem`)**| FORENSICS| `vol -f <file> windows.pslist` | [skills/forensics/memory-volatility.md](file:///home/kali/reverse-skill/skills/forensics/memory-volatility.md) | Volatility 3 CLI |
| **Steganography (Image / Audio / File)**| FORENSICS| `zsteg`, `binwalk`, `exiftool` | [skills/forensics/stego-carving.md](file:///home/kali/reverse-skill/skills/forensics/stego-carving.md) | [toolchain/triage.py](file:///home/kali/reverse-skill/toolchain/triage.py) |
| **PyJail Sandbox Escape** | MISC | AST subclass inspection | [skills/misc/pyjail-escape.md](file:///home/kali/reverse-skill/skills/misc/pyjail-escape.md) | [templates/solve_misc.py](file:///home/kali/reverse-skill/templates/solve_misc.py) |
| **Restricted Bash / RBash Jail** | MISC | Shell builtins check | [skills/misc/bash-jail.md](file:///home/kali/reverse-skill/skills/misc/bash-jail.md) | [templates/solve_misc.py](file:///home/kali/reverse-skill/templates/solve_misc.py) |

---

| **Z3 Inversion And Dynamic Extraction (collector)** | REV | `grep / triage collector` | [skills/rev/z3_inversion_and_dynamic_extraction.md](file:///home/kali/reverse-skill/skills/rev/z3_inversion_and_dynamic_extraction.md) | [work/rev/collector/solve.py](file:///home/kali/reverse-skill/work/rev/collector/solve.py) |

---

## 2. Fast Triage Protocol

When starting any challenge:
1. Run `python3 toolchain/triage.py ./work/<chal>/<file>` or inspect source code with [skills/audit/whitebox_triage.md](file:///home/kali/reverse-skill/skills/audit/whitebox_triage.md).
2. Match the triage output with the table above.
3. Open the corresponding playbook from `skills/<category>/` or `skills/audit/`.
4. Follow the ReAct reasoning protocol from [skills/audit/structured_reasoning.md](file:///home/kali/reverse-skill/skills/audit/structured_reasoning.md).
5. Copy the matching template from `templates/` to `./work/<chal>/solve.<ext>` and execute via `python3 ctf.py test <chal>`.
