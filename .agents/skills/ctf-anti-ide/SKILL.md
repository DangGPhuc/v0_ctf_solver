---
name: ctf-anti-ide
description: Autonomous CTF Lifecycle & Solving Agent Skill for Anti-IDE. Orchestrates tournament workflow (pulling challenges, lazy materialization in ephemeral runtime, ChatGPT triage, isolated execution, immediate flag submission) and connects with remote v0_ctf_knowledge.
argument-hint: "[pull|auto|solve|status|triage|instance|submit|env|knowledge] [args...]"
---

# Anti-IDE CTF Autonomous Lifecycle & Solver Skill

Operational skill enabling the Anti-IDE Agent to autonomously manage competition platforms (CTFd, GZCTF), interact with dynamic Docker containers, triage challenges via Strategic Advisor, execute experiments safely in isolated sandboxes, and submit flags immediately.

---

## 1. Quick Command Reference (`ctf` CLI)

All commands can be invoked via `ctf` (or `python -m ctf_core.cli.main`):

| Operation | Canonical CLI Command | Purpose |
| :--- | :--- | :--- |
| **All-in-One Auto** | `ctf auto -u <URL> -c "<COOKIE>"` | Đồng bộ tournament, nạp bài lazy, chạy vòng lặp ReAct khép kín tự động nộp cờ. |
| **Solve Challenge** | `ctf solve <ID> -u <URL>` | Giải bài cụ thể với vòng lặp ReAct, sandbox cách ly và nộp cờ tức thì. |
| **Triage & Fingerprint** | `ctf triage <ID>` | Bóc tách kiến trúc, mitigations (checksec), primitives và tìm Thẻ Tri Thức tương ứng. |
| **Set Auth / Config** | `ctf env set -u <URL> -c "<COOKIE>" -t "<TOKEN>"` | Ghi cấu hình vào `.env` cho Anti-IDE và solver scripts. |
| **Pull Event** | `ctf pull -u <URL>` (`--all` để tải attachment) | Đồng bộ metadata bài thi vào cache `.runtime/<event>/event.json` (mặc định lazy). |
| **Check Progress** | `ctf status` | Xem các challenge đang active trong ephemeral runtime `.runtime/`. |
| **Knowledge Doctor** | `ctf knowledge doctor` | Chẩn đoán kết nối GitHub REST Contents API tới kho tri thức ngoại vi. |
| **Dynamic Instance** | `ctf instance start <ID>` / `stop <ID>` | Bật/tắt dynamic container, tự động nhận `HOST:PORT`. |
| **Submit Flag** | `ctf submit <ID> -f "FLAG{...}"` | Nộp flag tức thì để ăn điểm; cảnh báo can thiệp thủ công nếu platform lỗi. |
| **Cleanup Runtime** | `ctf cleanup --challenge <ID>` / `--all` | Dọn dẹp an toàn ephemeral runtime sau khi giải xong bài. |

---

## 2. Quy Trình Tự Động Hóa Khép Kín (Closed-Loop ReAct)

```text
[Platform] ──> [Triage & Fingerprint] ──> [Remote Knowledge Retrieval]
                       │
                       ▼
             [Strategic Advisor]
                       │
                       ▼
           [Typed Execution Plan]
                       │
                       ▼
            [Isolated Sandbox Executor]
                       │
                       ▼
              [Evidence Evaluation]
              ├── Confirmed ──> Continue / Flag Candidate ──> Submit ──> Distill Knowledge ──> Cleanup
              ├── Rejected  ──> Pivot Hypothesis
              └── Inconclusive ──> Refine Experiment
```

### Bước 1: Đồng Bộ & Nạp Bài Lazy (`ctf pull` / `ctf auto`)
- Metadata lưu trong cache `.runtime/<event>/event.json`.
- File đính kèm chỉ tải khi bài thi được kích hoạt giải.

### Bước 2: Deep Fingerprint & Truy Xuất Tri Thức Ngoại Vi
- Bóc tách kiến trúc, binary mitigations (checksec), web/crypto primitives qua `FingerprintEngine`.
- Tự động truy vấn Thẻ Tri Thức từ repo ngoại vi `DangGPhuc/v0_ctf_knowledge` qua GitHub Contents API.

### Bước 3: Tham Vấn Cố Vấn Chiến Lược (`Strategic Advisor`)
- Tổng hợp `StateCapsule` (Dữ kiện đã xác minh, giả thuyết active, kết quả thực nghiệm gần nhất, hints từ bài tương tự).
- Advisor trả về bản định hướng kèm **khối JSON `execution_plan` định kiểu** bắt buộc.
- CẤM chạy trực tiếp văn bản tự do; chỉ thực thi các `ExecutionAction` đã qua kiểm định policy.

### Bước 4: Thực Thi Sandbox Cách Ly (`ContainerExecutor` / `RestrictedLocalExecutor`)
- **Container Sandbox**: Chạy `--cap-drop=ALL`, `--security-opt=no-new-privileges`, `--network=none` mặc định.
- **Ranh giới Artifacts**:
  - `input:<file>`: Mount `/input:ro` (chỉ đọc, tuyệt đối không chỉnh sửa binary gốc).
  - `work:<file>`: Mount `/work:rw` (chứa `solve.py` / `solve.sage`, micro-PoCs, logs).
- **Toolchain Routing**: Điều phối image phù hợp với từng category (`pwn`, `crypto-sage`, `web`, `rev`).

### Bước 5: Đánh Giá Bằng Chứng, Nộp Flag & Chắt Lọc Tri Thức
- Bắt cờ khớp format regex -> Nộp flag tức thì qua `ctf submit`.
- Sau khi giải thành công:
  1. Trích xuất Winning Path từ `DiscoveryTree`.
  2. Tạo ứng viên Thẻ Tri Thức (không chứa plaintext flag hay rác nhị phân).
  3. Dọn dẹp sạch sẽ ephemeral runtime `.runtime/<event>/challenges/<id>/`.

---

## 3. Cấu Trúc Ephemeral Runtime Bắt Buộc

Khi giải một bài tập, Agent tuân thủ cấu trúc tạm thời trong `.runtime/`:

```text
.runtime/<event_id>/challenges/<challenge_id>/
├── input/       # READ-ONLY: File đính kèm gốc từ platform (chall.zip, vuln, elf...)
├── work/        # READ-WRITE: solve.py, solve.sage, micro-PoC scripts, outputs
└── .advisor/    # STATE MACHINE: state.json, guidance.md, latest_prompt.md
```

Toàn bộ thư mục `.runtime/` là tạm thời (ephemeral) và được dọn dẹp sạch sẽ sau khi giải xong bài.

---

## 4. Quy Chuẩn Vận Hành Giải Đấu & Vòng Đời Tự Hủy (Tournament Lifecycle & Teardown Protocol)

### 4.1. Vai Trò Người Thực Thi (Executors: Anti-IDE & OpenCode)
- **Anti-IDE** và **OpenCode** là **Executors chính thức**: trực tiếp quản lý terminal, filesystem, sandbox container, và các công cụ dịch ngược (IDA Pro MCP).
- **Strategic Advisor (ChatGPT Web)**: Cố vấn chiến lược, ban hành kế hoạch thực nghiệm có cấu trúc (`ExecutionAction`).

### 4.2. Quy Trình Khởi Động Giải Đấu Mới
Khi tham gia một giải đấu CTF mới:
1. **Tạo thư mục giải đấu**: Tạo thư mục mang tên giải đấu ngay trong repository (ví dụ: `<tournament_name>/`).
2. **Truy cập thư mục**: `cd <tournament_name>`
3. **Cung cấp Refresh Token / Credentials**: Cung cấp token phiên hoặc refresh token của giải đấu cho Agent:
   ```bash
   ctf env set -u "https://ctf.example.com" -c "session=..." -t "<REFRESH_TOKEN>"
   ```
4. **Kích hoạt Chu Trình Tự Động (Autonomous Loop)**:
   ```bash
   ctf auto --max-iter 10 --executor container
   ```
   Anti-IDE / OpenCode sẽ tự động:
   - Đồng bộ danh mục challenge (`ctf pull`).
   - Nạp bài lười (`lazy materialization`) khi giải.
   - Bóc tách `ChallengeFingerprint` và truy xuất Thẻ Tri Thức từ `v0_ctf_knowledge`.
   - Tham vấn Cố vấn chiến lược tạo `ExperimentProposal` và nhận `EXP-xxx` chuẩn tắc.
   - Chạy thực nghiệm cách ly, đánh giá bằng chứng, và nộp cờ ngay khi phát hiện (`ctf submit`).

### 4.3. Quy Trình Sàng Lọc Tri Thức & Xóa Sạch Cuối Giải (Post-Tournament Distillation & Zero-Bloat Teardown)
Khi giải đấu kết thúc:
1. **Sàng Lọc Tự Động (Knowledge Distillation)**:
   Anti-IDE kích hoạt chu trình rà soát toàn bộ cây khám phá (`DiscoveryTree`):
   - Trích xuất Winning Paths, kỹ thuật khai thác mới, và các anti-patterns đã xác thực.
   - Biên dịch thành các **Thẻ Tri Thức (Technique Cards)** và writeups cô đọng.
   - Xuất bản lên kho tri thức ngoại vi `DangGPhuc/v0_ctf_knowledge` (qua PR an toàn hoặc outbox staging).
2. **Tiêu Hủy Tuyệt Đối (Complete Folder Teardown)**:
   - Dọn dẹp sạch toàn bộ file nhị phân đính kèm, logs, micro-PoCs, scratchpads.
   - **Xóa bỏ hoàn toàn chính thư mục giải đấu `<tournament_name>/`** (`rm -rf <tournament_name>`).
   - Đảm bảo repository `v0_ctf_solver` luôn giữ nguyên tắc **Zero Permanent Event Bloat**: chỉ lưu trữ engine và agent skills, không bao giờ phình to theo thời gian.

