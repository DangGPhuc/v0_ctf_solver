# Tooling — checklist & lệnh nhanh

Kali Linux đã có sẵn phần lớn công cụ dưới đây. Kiểm tra bằng `which <tool>`
trước khi cài.

## Cài nhanh các thư viện Python CTF
```bash
pip install pwntools pycryptodome gmpy2 sympy requests httpx z3-solver angr
```

## PWN
| Công cụ | Dùng để |
|---------|---------|
| `pwntools` | viết exploit, kết nối remote/process |
| `gdb` + `pwndbg`/`gef` | debug động |
| `checksec` | xem mitigations (NX/PIE/Canary/RELRO) |
| `ROPgadget`, `ropper` | tìm gadget ROP |
| `one_gadget` | tìm magic gadget trong libc |
| `seccomp-tools` | dump/phân tích bộ lọc seccomp |
| libc-database | nhận diện libc & tính offset |

## CRYPTO
| Công cụ | Dùng để |
|---------|---------|
| SageMath | đại số, đường cong, lattice |
| `pycryptodome`, `gmpy2`, `sympy` | toán & primitives |
| CADO-NFS | factor lớn / discrete log |
| `RsaCtfTool` | tấn công RSA tự động |
| `z3-solver` | giải ràng buộc |

## WEB
| Công cụ | Dùng để |
|---------|---------|
| `requests`/`httpx` | tự động hoá HTTP |
| Burp Suite | proxy, sửa request |
| webhook.site / interactsh | nhận callback (XSS/SSRF) |
| browser devtools | debug DOM/JS |

## REV
| Công cụ | Dùng để |
|---------|---------|
| Ghidra / IDA | dịch ngược |
| `angr` | symbolic execution |
| `frida`, `qiling` | instrument / emulate |
| dnSpy/ILSpy, jadx, uncompyle6 | .NET / Java / Python |

## MISC / FORENSICS
| Công cụ | Dùng để |
|---------|---------|
| `binwalk`, `foremost` | tách file nhúng |
| `zsteg`, `steghide`, `exiftool`, stegsolve | stego |
| Wireshark / `tshark` | phân tích pcap |
| `volatility3` | memory forensics |
| `xortool`, CyberChef | encoding/XOR |

## Lệnh recon nhanh
```bash
file ./chal && checksec --file=./chal
strings -n 8 ./chal | less
binwalk ./chal
nc -v host port            # thử kết nối remote
```

---

# Trạng thái cài đặt trên máy này (cập nhật 2026-06-17)

## ✅ Python: dùng conda env `ctf` (Python 3.11)
Kích hoạt trước khi giải bài:
```bash
source ~/miniconda3/etc/profile.d/conda.sh && conda activate ctf
```
Đã cài: pwntools, z3-solver, pycryptodome, sympy, gmpy2, numpy, pillow,
capstone, ROPgadget, ropper, flask, requests, httpx, scapy, tqdm, pyrage,
protobuf, itsdangerous, unicorn, keystone-engine, angr.
CLI có sẵn trong env: `pwn`, `checksec`, `ROPgadget`, `ropper`.
> Lưu ý: giữ `setuptools<81` để unicorn còn `pkg_resources`.
> angr hạ z3-solver xuống 4.13 (vẫn dùng tốt).

## ✅ CLI hệ thống đã có
radare2/r2, objdump, readelf, nm, strings, file, nc, socat, openssl, john,
hashcat, binwalk, exiftool, tshark, wireshark, upx, ltrace, strace, gef.

## ✅ ĐÃ CÀI ĐỦ bộ cốt lõi (24/24 CLI)
apt: gdb, gdbserver, steghide, foremost, docker, qemu-system ✅
gem: zsteg, seccomp-tools, one_gadget ✅ (ở /usr/local/bin)

## ⏳ Chỉ cài khi gặp bài cần
ltrace, strace   → sudo apt install -y ltrace strace
gef (plugin gdb) → echo "source /usr/share/gef/gef.py" >> ~/.gdbinit
SageMath, nsjail, volatility3, ghidra → xem lệnh bên dưới

### Lệnh cài
```bash
# apt
sudo apt update && sudo apt install -y gdb gdbserver steghide foremost \
  docker.io qemu-system qemu-utils

# pwndbg (không có trong apt Kali) — cài từ git
git clone https://github.com/pwndbg/pwndbg ~/tools/pwndbg && \
  cd ~/tools/pwndbg && ./setup.sh
# (hoặc dùng gef đã có sẵn: echo "source /usr/share/gef/gef.py" >> ~/.gdbinit)

# gem tools
sudo gem install zsteg seccomp-tools one_gadget

# SageMath: nặng, cài qua conda-forge nếu cần crypto đại số
conda create -y -n sage -c conda-forge --override-channels sage

# volatility3 (forensics, cài vào env ctf)
conda activate ctf && python -m pip install volatility3

# nsjail: build từ nguồn khi cần chạy challenge kCTF local
# https://github.com/google/nsjail
```

---

# Công cụ nhóm TJCSec (tjcsec.club) thực dùng trong writeup

Thống kê từ 40 writeup (xem `tjcsec-writeups/INDEX.md`). Tất cả đều đã cài
trên máy (env `ctf` + CLI hệ thống), trừ vài thứ ghi chú riêng.

| Công cụ | Tần suất | Trạng thái | Ghi chú |
|---------|----------|-----------|---------|
| pwntools (`from pwn import *`) | rất cao | ✅ env ctf | Xương sống mọi bài pwn |
| pycryptodome (`Crypto`) | cao | ✅ env ctf | Crypto |
| `nc` / netcat | cao | ✅ | Kết nối service |
| requests | cao | ✅ env ctf | Web automation |
| **Ghidra** | cao | ⏳ cài khi cần | Dịch ngược (rev) — chưa cài |
| curl | cao | ✅ | Web |
| docker | trung | ✅ | Tái lập challenge local |
| angr | trung | ✅ env ctf | Symbolic execution (rev) |
| strings, xxd, objdump | trung | ✅ | Recon binary |
| Wireshark / tshark | trung | ✅ | Forensics/network |
| **CyberChef** | trung | 🌐 web | Encoding/giải mã nhanh (gchq.github.io/CyberChef) |
| scapy | trung | ✅ env ctf | Network/packet |
| SageMath | trung | ⏳ cài khi cần | Crypto đại số |
| gdb + gef | trung | ✅ | Debug động (gef: thêm vào ~/.gdbinit) |
| numpy | thấp | ✅ env ctf | |
| radare2 | thấp | ✅ | |
| stegsolve, steghide | thấp | steghide ✅ / stegsolve ⏳ | Stego (stegsolve là .jar Java) |
| one_gadget | thấp | ✅ | |

## Ngôn ngữ solve script họ dùng
Python (áp đảo, ~114 block) > C (55, cho pwn/rev) > NASM (shellcode) >
TypeScript/JS (web) > C# (rev .NET) > bash. → Mặc định viết solver bằng
**Python + pwntools**; C/NASM khi cần shellcode hoặc tốc độ.

## Còn thiếu nên cài khi gặp bài rev/stego
```bash
# Ghidra (rev — TJCSec dùng nhiều nhất cho dịch ngược)
sudo apt install -y ghidra   # hoặc tải từ ghidra-sre.org
# stegsolve (stego, file .jar — cần java)
sudo apt install -y default-jre
# tải stegsolve.jar từ http://www.caesum.com/handbook/Stegsolve.jar
```
