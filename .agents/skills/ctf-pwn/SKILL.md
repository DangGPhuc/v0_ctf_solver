---
name: ctf-pwn
description: |
  CTF Binary Exploitation Playbook Suite.
  Covers Stack Exploitation (Ret2Win, Ret2Libc, ROP, SROP, Ret2csu), Heap Exploitation (Glibc 2.23-2.39: Tcache, Fastbin, Unsorted/Largebin, House of *),
  Format Strings (%p leak, %n arbitrary write), Kernel Exploitation, and Seccomp Sandbox Escapes.
---

# CTF PWN Exploitation Suite

## Triage & Execution Flow
1. **Initial Inspection**:
   ```bash
   file ./vuln
   checksec --file=./vuln
   ```
2. **Template Initialization**:
   ```bash
   cp ../../templates/solve_pwn.py ./solve.py
   ```
3. **Execution Mode**:
   - `python3 solve.py --local` (Run local subprocess)
   - `python3 solve.py --remote host port` (Connect to CTF server)
   - `python3 solve.py --gdb` (Attach GDB with custom breakpoints)

## Playbooks in this Module
- [stack-pwn.md](v0_ctf_knowledge/references/pwn/stack-pwn.md): Ret2text, Ret2libc, ROP chains, SROP, Ret2csu, Stack Pivoting.
- [heap-pwn.md](v0_ctf_knowledge/references/pwn/heap-pwn.md): Glibc 2.23-2.39 heap techniques, Tcache poisoning, Safe-linking bypass, House of Apple/Cat/Botcake.
- [format-string.md](v0_ctf_knowledge/references/pwn/format-string.md): Memory leakage and `%n` arbitrary write techniques.
- [kernel-pwn.md](v0_ctf_knowledge/references/pwn/kernel-pwn.md): QEMU kernel debugging, slab UAF, `commit_creds`, `ret2usr`, KPTI trampoline.
- [sandbox-escape.md](v0_ctf_knowledge/references/pwn/sandbox-escape.md): Seccomp bypasses, Open-Read-Write (ORW) shellcodes.
