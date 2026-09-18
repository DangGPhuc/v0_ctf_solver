# CTF Detailed Tactical Routing (skills/routing.md)

This document provides deep technical criteria to route challenges to the exact playbook and exploit strategy.

---

## 1. PWN (Binary Exploitation) Detailed Routing

### 1.1 Stack Exploitation
- **No Canary + No PIE + NX disabled**: Direct Shellcode execution on stack. $\rightarrow$ [skills/pwn/stack-pwn.md](file:///home/kali/reverse-skill/skills/pwn/stack-pwn.md)
- **No Canary + No PIE + NX enabled**: Ret2libc / Ret2text.
- **Canary + PIE enabled**:
  1. Leak Canary and Code/Libc Base via format string, partial overwrite, or buffer overread.
  2. Construct ROP Chain with `pop rdi; ret` $\rightarrow$ `system("/bin/sh")`.
  3. Fix 16-byte stack alignment with an extra `ret` gadget.
- **Limited Gadgets**:
  - `ret2csu` (control `r12`-`r15`, `rbx`, `rbp`, `rdx`, `rsi`, `edi`).
  - SROP (`sigreturn` syscall to control all registers simultaneously).

### 1.2 Heap Exploitation (Glibc Version Matrix)
- **Glibc 2.23 / 2.26**:
  - Fastbin Dup (Double Free $\rightarrow$ Arbitrary Write to `__malloc_hook`).
  - Unsorted Bin Attack (Write `main_arena` address to arbitrary pointer).
  - House of Orange (Top chunk shrink $\rightarrow$ `_IO_FILE` vtable hijacking).
- **Glibc 2.27 - 2.31**:
  - Tcache Poisoning (Overwrite `next` pointer in freed tcache entry $\rightarrow$ Allocate at arbitrary address).
  - Tcache Stashing Unlink (Combine smallbin with tcache to trigger arbitrary write).
  - House of Botcake (Double free across tcache and unsorted bin).
- **Glibc 2.32 - 2.34+ (Safe-Linking Pointer Mangling Enabled)**:
  - Pointer demangling: `mangled = (pos >> 12) ^ target`. Leak heap base first.
  - Safe-linking bypass for tcache/fastbins.
- **Glibc 2.34+ (`__malloc_hook` / `__free_hook` removed)**:
  - FSOP (File Structure Oriented Programming): Hijack `_IO_2_1_stdout_` or `_IO_list_all`.
  - House of Apple 2 (`_IO_wfile_overflow` $\rightarrow$ `_IO_cookie_jumps`).
  - House of Cat / House of Emma.

---

## 2. REVERSE ENGINEERING Detailed Routing

### 2.1 Constraint Satisfaction Problems (SMT / Z3)
- **Signature**: Linear equations, matrix multiplication, byte substitutions, XOR chains, polynomial evaluation.
- **Action**: Extract constraints from IDA Pro pseudo-C into Z3 BitVectors `BitVec('c_%d', 8)` $\rightarrow$ [skills/rev/z3-solver.md](file:///home/kali/reverse-skill/skills/rev/z3-solver.md).

### 2.2 Symbolic Execution (Angr)
- **Signature**: Multiple conditional branches, maze exploration, state machines with clear success/fail addresses.
- **Action**: Use `angr.Project` with `simgr.explore(find=..., avoid=...)` $\rightarrow$ [skills/rev/angr-symbolic.md](file:///home/kali/reverse-skill/skills/rev/angr-symbolic.md).

### 2.3 Virtual Machine & Custom Bytecode
- **Signature**: Dispatch loop `while(pc < len) { switch(code[pc]) { ... } }`, virtual registers array.
- **Action**: Identify opcode semantics $\rightarrow$ Write Python disassembler/decompiler $\rightarrow$ [skills/rev/vm-reversing.md](file:///home/kali/reverse-skill/skills/rev/vm-reversing.md).

### 2.4 Control Flow Deobfuscation (OLLVM)
- **Signature**: Huge switch-case with state dispatcher variable, high cyclomatic complexity, bogus control flow.
- **Action**: Trace basic block executions, reconstruct control flow graph $\rightarrow$ [skills/rev/deobfuscation.md](file:///home/kali/reverse-skill/skills/rev/deobfuscation.md).

---

## 3. CRYPTOGRAPHY Detailed Routing

### 3.1 RSA & Factoring Attacks
- $e = 3$ and small $m$: Direct cube root ($m = \sqrt[3]{c}$).
- Small $d$ ($d < \frac{1}{3} N^{0.25}$): Wiener's continued fraction attack.
- Moderate $d$ ($d < N^{0.292}$): Boneh-Durfee lattice attack.
- Related Messages ($m_1, m_2 = f(m_1)$): Franklin-Reiter Related Message attack.
- Small difference $|p - q| < N^{0.25}$: Fermat factorization.
- Coppersmith Small Roots: Known high/low bits of $p$ or $m$ $\rightarrow$ [skills/crypto/rsa-attacks.md](file:///home/kali/reverse-skill/skills/crypto/rsa-attacks.md).

### 3.2 Lattice-Based Cryptography
- **Hidden Number Problem (HNP)**: Partial ECDSA nonce leak $\rightarrow$ Construct CVP/Kannan lattice matrix $\rightarrow$ LLL reduction.
- **Knapsack Cryptosystems**: Merkle-Hellman knapsack solved via Lagarias-Odlyzko lattice reduction.
- **LWE / Learning With Errors**: Babai's Nearest Plane algorithm $\rightarrow$ [skills/crypto/lattice-attacks.md](file:///home/kali/reverse-skill/skills/crypto/lattice-attacks.md).

### 3.3 PRNG State Reconstruction
- **Mersenne Twister (MT19937)**: 624 outputs of 32-bit integers $\rightarrow$ Untemper state via `randcrack` to predict all future/past outputs $\rightarrow$ [skills/crypto/prng-attacks.md](file:///home/kali/reverse-skill/skills/crypto/prng-attacks.md).
- **Linear Congruential Generator (LCG)**: $X_{n+1} = (aX_n + c) \pmod m$. Solve for $a, c, m$ with 6 consecutive values.

---

## 4. WEB EXPLOITATION Detailed Routing

- **Blind SQL Injection**: Boolean-based or Time-based binary search using `httpx` async workers. $\rightarrow$ [skills/web/sqli-injection.md](file:///home/kali/reverse-skill/skills/web/sqli-injection.md).
- **Server-Side Template Injection (SSTI)**: Identify template engine (Jinja2, Twig, Thymeleaf, Spring) $\rightarrow$ Bypass filters $\rightarrow$ RCE $\rightarrow$ [skills/web/ssti-payloads.md](file:///home/kali/reverse-skill/skills/web/ssti-payloads.md).
- **Authentication & JWT**: Algorithm confusion (`none`, RS256 $\rightarrow$ HS256), Key ID injection (`kid`), JKU spoofing $\rightarrow$ [skills/web/auth-jwt-oauth.md](file:///home/kali/reverse-skill/skills/web/auth-jwt-oauth.md).
- **Prototype Pollution**: Server-side Node.js pollution gadgets (`child_process`, `execArgv`, template rendering) $\rightarrow$ [skills/web/prototype-pollution.md](file:///home/kali/reverse-skill/skills/web/prototype-pollution.md).
- **Insecure Deserialization**: Python pickle/yaml, PHP object injection (`__wakeup`, phar wrapper), Java `ysoserial` chains $\rightarrow$ [skills/web/deserialization.md](file:///home/kali/reverse-skill/skills/web/deserialization.md).

---

## 5. FORENSICS & MISC Detailed Routing

- **PCAP Stream Reconstruction**: `tshark -r stream.pcap -Y "http.request.method == POST"` or extract media/files via `tshark --export-objects`.
- **Memory Forensics**: Volatility 3 plugins for Linux and Windows.
- **PyJail Sandbox Escape**: Traverse `().__class__.__bases__[0].__subclasses__()` to invoke `os.system` without blocked characters.
