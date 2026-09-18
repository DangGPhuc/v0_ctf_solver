---
name: ctf-anti-ide
description: Autonomous CTF Lifecycle & Solving Agent Skill for Anti-IDE. Orchestrates tournament workflow (pulling challenges, starting/stopping dynamic containers, ChatGPT triage on Firefox, immediate flag submission) and connects with the reverse-skill playbooks (Pwn, Rev with IDA Pro MCP, Crypto, Web, Forensics).
argument-hint: "[pull|auto|chatgpt|status|instance|submit|env] [args...]"
---

# Anti-IDE CTF Autonomous Lifecycle & Solver Skill

Unified operational skill enabling the Anti-IDE Agent to autonomously manage competition platforms (CTFd, GZCTF), interact with dynamic Docker containers, triage challenges via ChatGPT Web on Firefox, exploit challenges using the local `reverse-skill` repository, and submit flags immediately.

---

## 1. Quick Command Reference (`./ctf` CLI)

All commands can be invoked via the workspace launcher `./ctf` (or `python3 ctf_suite/ctf.py`):

| Operation | Canonical CLI Command | Purpose |
| :--- | :--- | :--- |
| **All-in-One Auto** | `./ctf auto -u <URL> -c "<COOKIE>"` | Đăng nhập, crawl bài, dựng workspace 4 tầng, sync sang `reverse-skill`, sinh prompt ChatGPT cho toàn bộ challenge. |
| **Set Auth / Config** | `./ctf env set -u <URL> -c "<COOKIE>" -t "<TOKEN>"` | Ghi cấu hình vào `.env` cho Anti-IDE và các solver scripts. |
| **Pull Event** | `./ctf pull -u <URL> -o <DIR>` | Crawl bài, tải đính kèm song song, dựng workspace 4 tầng chuẩn. |
| **Advisor Init** | `./ctf advisor init <ID>` | Khởi tạo state.json, findings.md, hypotheses.md, experiments.jsonl cho challenge. |
| **Advisor Consult** | `./ctf advisor consult <ID>` | Đóng gói L0-L3 context, gọi Oracle Browser Bridge trao đổi trực tiếp với ChatGPT Web. |
| **Advisor Report** | `./ctf advisor report <ID> -e <EXP_ID> -s <STATUS>` | Báo cáo thực nghiệm, kiểm soát Hypothesis Budget và tự động followup phiên tư vấn. |
| **Advisor Escalate** | `./ctf advisor escalate <ID> -r "<REASON>"` | Kích hoạt PAL MCP thẩm định chéo khi bế tắc quá 2 lần thử nghiệm thất bại. |
| **Check Progress** | `./ctf status -w <DIR>` hoặc `./ctf advisor status <ID>` | Xem tiến độ giải, dashboard ReAct, ngân sách giả định. |
| **Start Container** | `./ctf instance start <CHALLENGE_ID> -w <DIR>` | Bật container, tự động cập nhật `HOST:PORT` vào `solve.py`. |
| **Stop Container** | `./ctf instance stop <CHALLENGE_ID> -w <DIR>` | Tắt container khi đã giải xong bài. |
| **Submit Right Away** | `./ctf submit --id <ID> -f "FLAG{...}"` | Nộp flag tức thì để ăn điểm; cảnh báo nộp tay nếu có lỗi. |
| **Auto Submit All** | `./ctf submit --auto -w <DIR>` | Quét toàn bộ workspace tìm `flag.txt` và nộp tất cả flag mới. |

---

## 2. Quy Trình Tự Động Hóa Khép Kín 5 Bước

Khi User cung cấp **URL** và **Cookie / Token**, Agent sẽ kích hoạt chu trình:

```text
[1. Auth & Pull] ---> [2. Triage & ChatGPT Web] ---> [3. Sync reverse-skill] ---> [4. Run Exploits] ---> [5. Submit Flag]
```

### Bước 1: Tiếp nhận & Đăng nhập (`./ctf auto`)
- Ghi cấu hình vào `.env` và cào toàn bộ bài tập.
- Đồng bộ bài tập vào thư mục làm việc của `reverse-skill/work/<category>/<chall_name>/`.
- Báo cáo cho User: Số lượng challenge, điểm số, danh mục.

### Bước 2: Tự Động Khởi Tạo State & Tham Vấn Strategic Advisor (`./ctf advisor`)
- Chạy `./ctf advisor init <ID>`:
  1. Tự động bóc tách chữ ký tĩnh, checksec, strings chắt lọc vào `.advisor/findings.md`.
  2. Tạo tracker giả thuyết `.advisor/hypotheses.md` và log thực nghiệm `.advisor/experiments.jsonl`.
- Chạy `./ctf advisor consult <ID>`:
  1. Tổng hợp **Ngữ Cảnh 4 Tầng** (L0 Đề bài, L1 Findings, L2 Hypotheses, L3 Code snippets).
  2. Gửi sang ChatGPT Web qua **Oracle CLI** (`--engine browser --browser-attach-running`).
  3. ChatGPT Web trả về bản định hướng 6 phần (`ASSESSMENT`, `HYPOTHESES`, `NEXT_ACTIONS`...) lưu tại `.advisor/guidance.md`.
  *(Nếu máy chưa bật debug port, hệ thống tự kích hoạt Fallback đẩy prompt vào Clipboard qua xclip).*

### Bước 3: Thực Thi Kỹ Thuật (Anti-IDE / OpenCode Executor)
- Executor đọc `NEXT_ACTIONS` từ `.advisor/guidance.md` và phối hợp với [reverse-skill](file:///home/kali/Documents/cyber_thread/reverse-skill):
  - **Dynamic Container**: Gọi `./ctf instance start <ID>` lấy IP:PORT.
  - **Reverse Engineering**: Dùng IDA Pro MCP server (`ida_decompile`, `ida_get_xrefs`).
  - **Pwn / Crypto / Web**: Viết script micro-PoC trong `script/`, hoàn thiện exploit trong `solver/solve.py`.
- **Báo cáo vòng lặp sau mỗi thực nghiệm**:
  ```bash
  ./ctf advisor report <ID> -e EXP-001 -a "<thao_tac>" -o "<hien_tuong>" -s CONFIRMED -d "<phan_tich>"
  ```
  Oracle sẽ tự động gửi `--followup` vào session để nhận chỉ dẫn vòng tiếp theo.

### Bước 3b: Phá Vỡ Bế Tắc Bằng Thẩm Định Chéo PAL MCP (Escalation)
- Nếu một hướng thử nghiệm thất bại 2 lần liên tiếp (`budget: 2 fails`):
  - Trạng thái bài chuyển sang `STALLED`.
  - Executor kích hoạt thẩm định chéo:
    ```bash
    ./ctf advisor escalate <ID> -r "<mô tả điểm nghẽn và giả định nghi ngờ sai>"
    ```
  - PAL MCP (`challenge`, `thinkdeep`) đưa ra góc nhìn phản biện độc lập và tự động nạp kết quả vào phiên làm việc của Strategic Advisor để đổi mới chiến lược!

### Bước 4: Chạy Exploit & Thu hoạch Flag
- Chạy `python3 solver/solve.py` -> bắt cờ khớp regex format (mặc định `FLAG{...}`).
- Ghi cờ vào `solver/flag.txt`.

### Bước 5: Nộp Flag Tức Thì (`ctf_submit_right_away`)
- Thực thi ngay:
  ```bash
  ./ctf submit --id <ID> -f "<FLAG>"
  ```
- **Nếu thành công**: Cập nhật `solved` trong `challenges.json`, chúc mừng và chuyển ngay sang bài tiếp theo!
- **Nếu thất bại (Rate limit / Lỗi xác thực)**: Bật khung cảnh báo to rõ `🚨 MANUAL INTERVENTION REQUIRED`, in chuỗi Flag để User **copy và nộp tay trên trình duyệt web**.

---

## 3. Quy Tắc Tổ Chức Workspace 4 Tầng Cho Agent

Khi giải một bài tập, Agent **BẮT BUỘC** tuân thủ cấu trúc 4 thư mục:

```text
<Workspace>/<Category>/<Challenge_Name>/
├── challenge/       # NGUYÊN BẢN: Đề bài (README.md), metadata.json, file đính kèm (chall, zip...)
├── script/          # THỬ NGHIỆM: chatgpt_prompt.md, chatgpt_guidance.md, scripts nháp, fuzzing
├── solver/          # CHÍNH THỨC: solve.py chuẩn hoàn chỉnh để lấy flag
└── writeup/         # BÁO CÁO: Ghi chú phân tích lỗ hổng và các bước khai thác
```

---

## 4. Tích Hợp Sâu Kho Kỹ Năng [reverse-skill](file:///home/kali/Documents/cyber_thread/reverse-skill)

Toàn bộ bản sao vật lý của `reverse-skill` đã nằm tại `/home/kali/Documents/cyber_thread/reverse-skill`:
- **Pwn**: [.agents/skills/ctf-pwn/](file:///home/kali/Documents/cyber_thread/.agents/skills/ctf-pwn/) (Heap, ROP, Stack, Kernel)
- **Rev**: [.agents/skills/ctf-rev/](file:///home/kali/Documents/cyber_thread/.agents/skills/ctf-rev/) (IDA Pro MCP Playbook, Z3 Solver, Angr)
- **Web**: [.agents/skills/ctf-web/](file:///home/kali/Documents/cyber_thread/.agents/skills/ctf-web/) (Blind SQLi, SSTI, Deserialization, Prototype Pollution)
- **Crypto**: [.agents/skills/ctf-crypto/](file:///home/kali/Documents/cyber_thread/.agents/skills/ctf-crypto/) (RSA attacks, Lattice LLL, ECC, PRNG)
- **Forensics**: [.agents/skills/ctf-forensics/](file:///home/kali/Documents/cyber_thread/.agents/skills/ctf-forensics/) (PCAP, Volatility, Stego)
- **Audit**: [.agents/skills/ctf-audit/](file:///home/kali/Documents/cyber_thread/.agents/skills/ctf-audit/) (Whitebox triage, ReAct reasoning protocol)
