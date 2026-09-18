# Methodology theo từng category

Mỗi category dưới đây gồm: cách nhận diện → công cụ → các hướng tấn công phổ biến.

---

## PWN (binary exploitation)

**Nhận diện:** file ELF/PE, kết nối qua `nc host port`, đề nhắc tới buffer/heap.

**Recon:**
- `file ./chal`, `checksec --file=./chal` (NX, PIE, Canary, RELRO).
- `strings`, `nm`, `objdump -d`, mở bằng Ghidra/IDA/Binary Ninja.
- Xác định libc version (`strings libc.so | grep "GNU C"`, hoặc dùng libc-database).

**Hướng tấn công thường gặp:**
- Stack buffer overflow → ret2win / ret2libc / ROP chain.
- Format string (`%n`, `%p` leak) → arbitrary read/write.
- Heap: use-after-free, double free, tcache poisoning, fastbin dup, House of *.
- Integer overflow / off-by-one.
- Leak (PIE/libc) rồi tính base, bypass ASLR.

**Công cụ:** `pwntools` (Python), `gdb` + `pwndbg`/`gef`, `ROPgadget`/`ropper`,
`one_gadget`, `seccomp-tools` (cho sandbox/seccomp).

**Solve script mẫu (pwntools):**
```python
from pwn import *
context.binary = elf = ELF('./chal')
libc = ELF('./libc.so.6')
# io = process('./chal')
io = remote('host', 1337)
# ... build payload ...
io.sendline(payload)
io.interactive()  # hoặc đọc flag tự động
```

---

## CRYPTO

**Nhận diện:** đề cho ciphertext, public key, params toán học; có `chall.py`
mô tả scheme.

**Recon:** đọc kỹ source — kiểu mã hoá (RSA, ECC, AES, DH, Schnorr…), tham số,
chỗ random yếu / reuse.

**Hướng tấn công thường gặp:**
- RSA: e nhỏ (cube root), modulus chung, Wiener (d nhỏ), Fermat (p~q),
  Hastad broadcast, partial key (Coppersmith).
- AES: ECB pattern/cut-and-paste, CBC bit-flipping, padding oracle, nonce reuse (CTR/GCM).
- ECC/DLP: invalid curve, small subgroup, Pohlig-Hellman, MOV, group đẳng cấu
  về `k*` (xem crypto-cursved 2023).
- PRNG yếu (Mersenne Twister recover), LCG, time-seeded.
- Hash length extension.

**Công cụ:** SageMath (đại số/curve), `pycryptodome`, `gmpy2`, `sympy`,
CADO-NFS / `cado-nfs` (discrete log, factor lớn), `RsaCtfTool`, `z3` (constraint).

---

## WEB

**Nhận diện:** URL/host HTTP, source web app, thường có biến thể `-bot`
(admin bot dùng cho XSS/CSRF).

**Recon:** đọc source server, xem framework, route, cách render, cookie/JWT,
CSP header. `-bot` nghĩa là cần XSS để đánh cắp cookie/flag của admin.

**Hướng tấn công thường gặp:**
- XSS (reflected/stored/DOM) → exfil cookie tới webhook của mình.
- SQLi / NoSQLi.
- SSRF, SSTI (server-side template injection).
- Prototype pollution, deserialization.
- Path traversal / LFI, file upload.
- JWT (alg=none, weak secret, key confusion), auth bypass.
- Race condition, IDOR.
- CSP bypass (cho postMessage/DOM clobbering — xem các bài postviewer).

**Công cụ:** `requests`/`httpx` (Python), Burp Suite, browser devtools,
webhook.site / interactsh để nhận callback, `sqlmap` (cẩn thận), nuclei.

---

## REV (reverse engineering)

**Nhận diện:** binary/bytecode cần hiểu logic để tạo input đúng (keygen,
crackme, VM).

**Recon:** `file`, `strings`. Mở bằng Ghidra/IDA. Với .NET → dnSpy/ILSpy;
Java → jadx/procyon; Python → `uncompyle6`/`decompyle3`, pyinstaller extract;
Rust/Go → có symbol khó đọc, dùng cấu trúc.

**Hướng làm:**
- Đọc logic kiểm tra flag, đảo ngược phép biến đổi.
- Dynamic: chạy trong gdb/x64dbg, đặt breakpoint chỗ so sánh.
- Symbolic execution với `angr` để solve constraint tự động.
- VM-based obfuscation: dựng lại disassembler cho bytecode tùy biến.

**Công cụ:** Ghidra, IDA, `angr`, `unicorn`, `frida`, `qiling`.

---

## MISC / FORENSICS

**Nhận diện:** file ảnh/pcap/disk/log, đề mơ hồ, dạng "tìm flag trong dữ liệu".

**Hướng làm:**
- File analysis: `file`, `binwalk -e`, `foremost`, `strings -el`.
- Stego: `zsteg` (PNG), `steghide`, `exiftool`, `stegsolve`, LSB.
- Network: Wireshark/`tshark`, theo dõi TCP stream, trích file từ pcap.
- Disk/memory: `volatility3` (memory dump), `testdisk`, `photorec`.
- Encoding: base64/32/85, hex, ROT, XOR brute (`xortool`), magic với CyberChef.

---

## HARDWARE / SANDBOX / PYJAIL

- **Hardware:** đọc datasheet/HDL, simulate logic, phân tích tín hiệu.
- **Sandbox escape:** vượt seccomp/nsjail/chroot — `seccomp-tools dump`, tìm
  syscall bị chặn, orw shellcode (open/read/write flag) nếu execve bị cấm.
- **Pyjail:** thoát hạn chế Python — bypass filter, `__builtins__` recovery,
  audit hook bypass, dùng `().__class__.__bases__` chains.

---

## Mẹo chung

- Luôn kiểm tra format flag mong đợi và verify khớp trước khi nộp.
- Lưu lại các bước/PoC để viết writeup.
- Nếu bí, tìm challenge tương tự trong repo Google CTF (`solution/` folder) hoặc
  writeup CTFtime.
