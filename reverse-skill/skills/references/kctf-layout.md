# Cấu trúc challenge kiểu Google CTF / kCTF

Repo: https://github.com/google/google-ctf — tổ chức theo năm (`2017`…`2025`),
mỗi năm có `quals/` và đôi khi `hackceler8/`. Mỗi challenge là một thư mục tên
`category-challengename`, ví dụ:

- `pwn-write-flag-where`, `pwn-unicornel`
- `crypto-cursved`, `crypto-mceliece`
- `web-postviewer3`, `web-postviewer3-bot`
- `rev-arcade`, `misc-pycalc`

> ⚠️ Code trong các thư mục năm chứa lỗ hổng cố ý ("unfixed security
> vulnerabilities"). Không chạy trên production. Cô lập trong VM/container.

## Layout một challenge

```
category-name/
├── README.md          # mô tả / quickstart kCTF
├── challenge.yaml      # config deploy: name, namespace, ports, PoW difficulty
├── metadata.yaml       # name, category, description, flag, host (vd "chal.2023.ctfcompetition.com 1337")
├── challenge/          # Dockerfile + file challenge (source, binary, Makefile)
│   ├── Dockerfile
│   ├── nsjail.cfg      # cấu hình sandbox nsjail (nếu có)
│   └── ...             # chal.c / server.py / ...
├── attachments/        # file phát cho thí sinh (nếu có)
├── solution/           # solve script / writeup chính thức ← tham khảo rất tốt
└── healthcheck/        # (optional) kiểm tra sức khoẻ, dùng pwntools, /healthz :45281
```

### `metadata.yaml` — dùng để gì
Chứa `category`, `description`, và thường có cả `flag` (để verify offline) cùng
`host`/port của server remote. Đọc file này đầu tiên để biết loại bài và nơi kết nối.

### `challenge.yaml` — config deploy
Đổi name, namespace, port (mặc định challenge nhận kết nối ở port **1337**),
và độ khó proof-of-work.

## Build & test local

```bash
# Build challenge (đặc biệt quan trọng với pwn nếu binary deploy phải khớp)
make -C challenge

# Dựng bằng Docker để test offline
cd challenge && docker build -t chal . && docker run --rm -p 1337:1337 chal

# Kết nối thử
nc localhost 1337
```

- `kctf_setup` phải là lệnh đầu tiên trong `CMD` của Dockerfile.
- `nsjail` đã cài sẵn, cấu hình qua `challenge/nsjail.cfg`.
- Healthcheck (nếu dùng) trả lời GET `/healthz` ở port `45281`.

## Quy trình khi nhận một folder challenge

1. `cat metadata.yaml` → biết category, host, (flag để verify).
2. `cat README.md` → mô tả đề.
3. Xem `challenge/` → đọc source / lấy binary.
4. Nếu có `solution/` → tham khảo cách giải (nhưng tự viết lại để hiểu).
5. Build local → phát triển exploit → tự động hoá → bắn remote.
