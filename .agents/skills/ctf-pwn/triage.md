# Binary Exploitation (Pwn) Operational Triage

## 1. Initial Mitigation Checklist
Run checksec on binary:
- Arch: x86, x86-64, ARM, AArch64.
- Stack Canary: Present (requires leak/bypass) vs Absent (direct RIP control).
- NX: Enabled (requires ROP/ret2libc) vs Disabled (executable stack shellcode).
- PIE: Enabled (requires binary address leak) vs Disabled (fixed code section).
- RELRO: Full (GOT read-only) vs Partial (GOT overwrite possible).

## 2. Binary Linking & Symbols
- Static vs Dynamic: Statically linked binaries have static libc gadgets for direct syscall chains; dynamic binaries require libc leak.
- Stripped vs Unstripped: Symbols present indicate helper functions or win functions.

## 3. Sandboxing & Seccomp
- Run seccomp-tools dump on binary to identify blocked syscalls (e.g. execve blocked -> open/read/write chain).
