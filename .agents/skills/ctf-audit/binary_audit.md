# Static Binary & C Code Audit (skills/audit/binary_audit.md)

## 1. Unsafe Functions & Memory Sinks

| Unsafe C Function | Vulnerability Class | Primitive / Impact | Safer Alternative |
| :--- | :--- | :--- | :--- |
| `gets(buf)` | Stack Buffer Overflow | Unbounded read into stack $\rightarrow$ Direct RIP overwrite | `fgets(buf, size, stdin)` |
| `strcpy(dst, src)`, `strcat` | Buffer Overflow | Missing bounds check $\rightarrow$ Overwrite adjacent memory | `strncpy`, `strlcpy` |
| `sprintf(buf, fmt, ...)` | Buffer Overflow | Output length unbounded $\rightarrow$ Overwrite buffers | `snprintf(buf, size, fmt, ...)` |
| `printf(buf)` (1st arg user-controlled) | Format String Bug | Direct memory read (`%p`, `%s`) & write (`%n`, `%hn`, `%hhn`) | `printf("%s", buf)` |
| `read(fd, buf, count)` | Buffer Overflow / Off-by-one | If `count > sizeof(buf)` or off-by-one (`<=` vs `<`) | Check allocation size |
| `scanf("%s", buf)` | Buffer Overflow | `%s` without width specifier writes unbounded | `scanf("%63s", buf)` |
| `malloc(n * sizeof(T))` | Integer Overflow | `n * sizeof(T)` overflows $\rightarrow$ Under-allocated heap buffer | Check `n > SIZE_MAX / sizeof(T)` |
| `free(ptr)` (ptr not nullified) | Use-After-Free / Double Free | Pointer reused or freed twice $\rightarrow$ Heap corruption | `ptr = NULL` |

---

## 2. Checksec vs Mitigation Matrix

| Security Feature | Enabled Effect | Bypass / Triage Strategy |
| :--- | :--- | :--- |
| **Canary** | Stack cookie at `$rbp - 8` | Leak canary via Format String or Partial Read; OR overwrite stack via non-linear write. |
| **NX / DEP** | Stack/Heap not executable | ROP (Return Oriented Programming), ret2libc, ret2syscall. |
| **PIE / ASLR** | Binary & Libc bases randomized | Leak base address of binary/libc via format string or uninitialized memory. |
| **RELRO: Full** | GOT is read-only | Cannot overwrite GOT. Hijack hook pointers (`__malloc_hook`, `__free_hook`), return address, or `_IO_FILE` vtables. |
| **RELRO: Partial** | GOT is writable | Overwrite GOT entries (e.g. `puts@got` $\rightarrow$ `system`). |

---

## 3. Fast Static Binary Audit Workflow

1. **Checksec & Metadata**:
   - `checksec --file=<target>`
   - `file <target>` (32/64 bit, stripped/unstripped, statically/dynamically linked).
2. **Decompile & Function Triage**:
   - Locate `main` and all custom functions in IDA Pro / Ghidra.
   - Trace all calls to memory allocation (`malloc`, `calloc`) and freeing (`free`).
   - Look for uninitialized stack variables, off-by-one loop indices, and signed/unsigned comparison bugs (`int` vs `size_t`).
3. **Determine Primitive**:
   - Stack Overflow $\rightarrow$ ROP chain / ret2text / ret2libc.
   - Heap Overflow / UAF $\rightarrow$ Tcache poisoning / Fastbin dup / FSOP.
   - Format String $\rightarrow$ Arbitrary read/write.
