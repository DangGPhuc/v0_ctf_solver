---
name: ctf-advisor
description: CTF Dual-Agent Collaboration Protocol (Executor ↔ Advisor). Orchestrates iterative solving between Anti-IDE/OpenCode (Executor) and ChatGPT Web (Strategic Advisor via Oracle CLI/Browser bridge), utilizing BrowserSkill for web actuation and PAL MCP for consensus/escalation.
argument-hint: "[init|consult|report|escalate|status] [CHALLENGE_ID] [options]"
---

# CTF Dual-Agent Collaboration Protocol (Executor ↔ Strategic Advisor)

Quy chuẩn kỹ năng tác chiến phối hợp 2 AI Agent:
- **Executor (Anti-IDE / OpenCode)**: Agent thực thi tại chỗ (Terminal, GDB, IDA Pro MCP, Python runtime, file system).
- **Strategic Advisor (ChatGPT Web)**: Cố vấn chiến lược phân tích lỗ hổng gốc, đề xuất giả thuyết và định hướng thực nghiệm thông qua cầu nối **Oracle CLI/Browser Bridge**.
- **Browser Actuator (BrowserSkill)**: Thực thi duyệt web ngoại vi (tải challenge, tương tác portal thi đấu có auth).
- **Escalation & Consensus Layer (PAL MCP)**: Hội đồng thẩm định độc lập khi ChatGPT Web rơi vào bế tắc (tunnel vision).

---

## 1. Bảng Tham Chiếu Lệnh CLI (`./ctf advisor`)

| Lệnh CLI | Vai Trò | Mục Đích Tác Chiến |
| :--- | :--- | :--- |
| `./ctf advisor init <ID>` | Khởi tạo | Tạo cấu trúc `.advisor/` bên trong thư mục challenge (`state.json`, `findings.md`, `hypotheses.md`, `experiments.jsonl`, `tree.json`). |
| `./ctf advisor consult <ID>` | Tham vấn Vòng 1 / Tiếp theo | Gom ngữ cảnh 4 tầng (L0-L3), gửi prompt sang ChatGPT Web qua Oracle (`--engine browser --browser-attach-running`), bắt phản hồi và trích xuất `NEXT_ACTIONS`. |
| `./ctf advisor report <ID> -e <EXP_ID> -o "<OBSERVED>" -s <CONFIRMED\|REJECTED>` | Báo cáo kết quả | Đóng gói báo cáo thực nghiệm, cắt tỉa nhánh bế tắc trong cây DAG, kiểm soát Budget và tự động followup phiên tư vấn. |
| `./ctf advisor escalate <ID> -r "<REASON>"` | Hội chẩn đa mô hình | Kích hoạt PAL MCP (`challenge`, `thinkdeep`, `consensus`) để phá vỡ bế tắc khi hết ngân sách giả định. |
| `./ctf advisor status <ID>` | Giám sát ReAct | Hiển thị bảng điều khiển ReAct (Phase, Iteration, Active Hypothesis, Budget, Confidence). |
| `./ctf meta tree <ID>` | Cây Khám Phá DAG | Hiển thị đồ thị cây màu trực quan các nhánh giả thuyết, hành động, quan sát và nhánh pruned. |
| `./ctf meta replay <ID> -p <POLICY>` | Replay Simulator | Mô phỏng Replay một ExplorationPolicy ngoại tuyến trên DiscoveryTree lịch sử mà không cần gọi lại LLM. |
| `./ctf meta benchmark` | So sánh Policy A vs B | Chấm điểm và so sánh trực tiếp hiệu năng giữa 2 chính sách tác chiến trên toàn bộ dữ liệu lịch sử. |
| `./ctf meta compile <ID>` | Biên dịch Tri thức | Tự động trích xuất Winning Path và Anti-Patterns thành Thẻ Tri Thức (Technique Card). |
| `./ctf meta cards` | Tra cứu Tri thức | Liệt kê toàn bộ Thẻ Tri Thức đã tích lũy trong `knowledge_base/`. |
| `./ctf prompt capsule <ID>` | State Capsule | Hiển thị viên nang trạng thái chắt lọc (Confirmed Facts, Active Hypothesis, Pruned Dead-ends, Experience hints). |
| `./ctf prompt lint <ID> [-a agent]` | Prompt Linter | Quét và tự động vá 37 anti-patterns làm giảm hiệu suất reasoning (thiếu Stop Condition, trôi ngữ cảnh). |
| `./ctf prompt show <ID> [-a agent]` | Prompt Compiler | Xuất hợp đồng giao việc Template H (cho Executor) hoặc Template E: Auditable Reasoning (cho Advisor). |

---

## 2. Vòng Đời Tác Chiến State Machine 6 Bước

```text
[1. INIT] ──> [2. TRIAGE] ──> [3. CONSULT] ──> [4. EXECUTE] ──> [5. EVALUATE]
                                     ▲                                │
                                     │         [Progress]             │
                                     ├────────────────────────────────┤
                                     │      [Stalled > 2 fails]       │
                                     └─── [6. ESCALATE via PAL] ◄─────┘
                                                                      │
                                                               [Flag Found]
                                                                      ▼
                                                                [7. SOLVED]
```

### Bước 1: Khởi tạo Trạng thái (`./ctf advisor init <ID>`)
Tạo thư mục `.advisor/` tại workspace của challenge:
```text
<Challenge_Dir>/
├── .advisor/
│   ├── state.json           # Operational state (phase, session, iteration, budget)
│   ├── findings.md          # Các phát hiện đã xác minh (L1 Context)
│   ├── hypotheses.md        # Danh sách giả thuyết được xếp hạng (H1, H2)
│   ├── experiments.jsonl    # Lịch sử thực nghiệm chi tiết (EXP-001, EXP-002...)
│   └── guidance.md          # Chỉ dẫn mới nhất nhận từ ChatGPT Web
```

### Bước 2: Triage Cơ Bản (Fast Static Analysis)
- Executor chạy các công cụ tĩnh: `file`, `checksec`, `strings -n 7`.
- Nếu là Rev/Pwn phức tạp: Mở hàm `main`/`vuln` trên IDA Pro MCP (`ida_decompile`).
- Ghi nhận các dữ kiện tĩnh ban đầu vào `.advisor/findings.md`.

### Bước 3: Tham Vấn Cố Vấn (`./ctf advisor consult <ID>`)
- Hệ thống tự động tổng hợp **Ngữ Cảnh 4 Tầng (Context Hierarchy)**:
  - **Level 0 (Metadata)**: Tên bài, Category, Points, Connection Info, Hints, Description.
  - **Level 1 (Findings)**: Toàn bộ nội dung cập nhật trong `.advisor/findings.md`.
  - **Level 2 (Active Hypothesis & Experiments)**: Giả thuyết hiện tại và thực nghiệm gần nhất từ `experiments.jsonl`.
  - **Level 3 (Focused Artifacts)**: Tối đa 50 dòng decompiled code hoặc tham số crypto then chốt (TUYỆT ĐỐI không gửi toàn bộ binary dump).
- Oracle CLI gửi prompt sang Chrome đã login ChatGPT Web:
  - Gắn kèm chỉ thị chiến lược từ `templates/advisor_system_prompt.md`.
  - Bắt kết quả trả về, lưu vào `.advisor/guidance.md` và cập nhật `oracle_session` trong `state.json`.

### Bước 4: Thực Thi Nhiệm Vụ (Executor Action)
- Executor (Anti-IDE / OpenCode) đọc `NEXT_ACTIONS` trong `.advisor/guidance.md`.
- Tiến hành thực nghiệm:
  - Viết micro-PoC trong `script/`.
  - Chạy GDB, kiểm tra crash dump, trích xuất offset.
  - Test payload qua network socket / HTTP request.
  - Nếu gặp dynamic docker: Sử dụng `./ctf instance start <ID>` để lấy IP/Port.

### Bước 5: Đánh Giá & Báo Cáo (`./ctf advisor report <ID>`)
- Executor so sánh kết quả thực tế với `EXPECTED_RESULTS` của Advisor.
- Chạy lệnh:
  ```bash
  ./ctf advisor report <ID> \
    -e EXP-002 \
    -a "Chạy solve_rop.py kiểm tra stack alignment" \
    -o "Crash tại do_system+12 với SIGSEGV tại movaps" \
    -s REJECTED \
    -d "Cần chèn thêm 1 gadget ret để căn chỉnh 16-byte stack"
  ```
- **Nếu ra Flag**: Ghi vào `solver/flag.txt`, gọi `./ctf submit --id <ID> -f "<FLAG>"` ➔ Hoàn thành bài!
- **Nếu tiến triển tốt (Progress)**: Oracle tự động kích hoạt `--followup <session>` để xin chỉ dẫn tinh chỉnh tiếp theo.

---

## 3. Quy Tắc Ngân Sách Giả Thuyết (Hypothesis Budget Rule)

Để loại trừ hiện tượng AI Agent bị **sa lầy (tunnel vision)** vào một giả thuyết sai:
1. Mỗi giả thuyết $H_x$ có ngân sách tối đa **2 lần thực nghiệm thất bại** (`max_failures_per_hypothesis: 2`).
2. Nếu sau 2 lần thử nghiệm liên tiếp mà kết quả vẫn `REJECTED`:
   - Executor **CẤM** tiếp tục cố đấm ăn xôi.
   - Trạng thái chuyển sang `stalled`.
   - Kích hoạt cơ chế **Thẩm định chéo (Escalation)**.

---

## 4. Cơ Chế Thẩm Định Chéo Đa Mô Hình (Escalation Layer via PAL MCP)

Khi ChatGPT Web bị bế tắc hoặc hết ngân sách giả định, Executor gọi:
```bash
./ctf advisor escalate <ID> -r "ChatGPT đang bám vào hướng Heap UAF nhưng libc 2.35 có safe-linking và tcache zeroing"
```

Hệ thống sẽ:
1. Sử dụng công cụ `challenge` hoặc `thinkdeep` của **PAL MCP** (hỏi Gemini 1.5 Pro / Claude 3.5 Sonnet / Codex).
2. Thẩm định lại toàn bộ các giả định nền tảng (Assumptions Review).
3. Đóng gói kết luận từ mô hình thứ 2 gửi ngược lại phiên ChatGPT Web của Oracle:
   > *"Hội đồng thẩm định độc lập vừa phản biện: Giả định UAF không khả thi do cơ chế Safe Linking. Khuyến nghị tập trung vào hướng House of Apple hoặc Format String tại hàm log. Xin mời Lead Advisor đánh giá lại chiến lược."*

---

## 5. Kiến Trúc Bộ Nhớ 3 Tầng & Siêu Học Tự Hoàn Thiện (Dream-RSI Meta-Layer)

Hệ thống nâng cấp quy trình tích lũy tri thức thành mô hình 3 tầng phân định rạch ròi:

```text
                    PROJECT MEMORY ARCHITECTURE

             ┌─────────────────────────────────────────┐
             │       1. EPISODIC MEMORY (DAG)          │
             │                                         │
             │   .advisor/events.jsonl                 │
             │   .advisor/tree.json (Discovery Tree)   │
             └────────────────────┬────────────────────┘
                                  │
          ┌───────────────────────┴───────────────────────┐
          ▼                                               ▼
┌───────────────────────────────────┐   ┌───────────────────────────────────┐
│     2. PROCEDURAL MEMORY          │   │     3. DECLARATIVE KNOWLEDGE      │
│   policies/current.yaml           │   │   knowledge_base/cards/           │
│   (Branching, Stop Rules,         │   │   (Technique Cards, Winning Paths,│
│    Hypothesis Budgets, Timeouts)  │   │    Anti-Patterns, Primitives)     │
└─────────────────┬─────────────────┘   └───────────────────────────────────┘
                  │
                  ▼
┌───────────────────────────────────┐
│      OFFLINE REPLAY SIMULATOR     │
│   Duyệt lại không gian thực tế    │
│   Score candidate policy          │
│   Promote best policy             │
└───────────────────────────────────┘
```

1. **Episodic Memory (Cây Khám Phá DiscoveryTree)**: Mọi thao tác đều được số hóa thành nút DAG ($H \to A \to O$). Không bao giờ để lại log text vô dụng.
2. **Procedural Memory (Exploration Policy)**: Tách các quy tắc vận hành thành tệp YAML có phiên bản (`policies/default_v1.yaml`, `policies/fast_triage_v1.yaml`).
3. **Declarative Knowledge Base (Thẻ Tri Thức)**: Tự động trích xuất chuỗi chiến thắng (Winning Path) và các cạm bẫy đã thử thất bại (Dead-ends) thành thẻ tri thức độc lập, chỉ nạp đúng thẻ cần thiết vào bài mới.
4. **Replay Simulator Ngoại Tuyến**: Cho phép chạy benchmark so sánh hiệu năng các chính sách (`./ctf meta benchmark`) hoàn toàn offline để chọn ra chính sách tối ưu nhất trước khi bước vào giải đấu.

---

## 6. Prompt Master Engine & Tầng Biên Dịch Hợp Đồng (Prompt Compiler)

Nhúng nguyên lý thiết kế từ `prompt-master` để chuyển đổi quyết định từ Dream-RSI thành hợp đồng giao việc có tính ràng buộc pháp lý giữa 2 Agent:

```text
                  DREAM-RSI POLICY
                         │
                         ▼
                 PROMPT SPEC (9D)
                         │
                         ▼
                   STATE CAPSULE
                         │
                         ▼
                   PROMPT LINTER
                         │ (Auto-repair anti-patterns)
                         ▼
                  PROMPT COMPILER
                   │            │
    (Template E)   ▼            ▼   (Template H)
             ADVISOR            EXECUTOR
           (ChatGPT Web)     (Anti-IDE/OpenCode)
```

1. **Quy chuẩn ý định 9 chiều (`PromptSpec`)**:
   - `task_objective`, `task_type`, `target_agent`, `target_backend`, `state_capsule`
   - `allowed_scope`, `forbidden_scope`, `stop_conditions`, `evidence_contract`, `success_criteria`.
2. **Viên nang trạng thái (`StateCapsule`)**:
   - Không ném cả lịch sử thô (100k tokens) vào prompt gây context pollution.
   - Chỉ chắt lọc tối đa 8 confirmed facts, active hypothesis, danh sách các hướng đã thất bại (Rejected Dead-ends), 2-3 thực nghiệm gần nhất, và gợi ý từ thẻ tri thức (chỉ rõ là Hint, không phải Fact hiện tại).
3. **Template H: ReAct + Agentic Stop Conditions (Executor)**:
   - Quy định rõ ràng: Allowed actions, Forbidden actions, Stop conditions, Evidence contract và format báo cáo YAML bắt buộc (`status: CONFIRMED | REJECTED | INCONCLUSIVE`).
4. **Template E: Auditable Reasoning Protocol (Advisor)**:
   - Buộc ChatGPT Web trả lời theo 6 phần chuẩn: `ASSESSMENT`, `RANKED HYPOTHESES (H1, H2)`, `ASSUMPTIONS & UNCERTAINTY`, `SUPPORTING/CONTRADICTING EVIDENCE`, `NEXT ACTIONS`, `STOP CONDITIONS & BRANCHES TO PRUNE`.
5. **Prompt Linter (37 Anti-Patterns Guardrail)**:
   - Phát hiện các lỗi chí mạng: thiếu Stop Condition, không giới hạn phạm vi, lặp lại nhánh đã Rejected, thiếu hợp đồng bằng chứng. Tự động vá (Auto-Repair) trước khi xuất prompt.

---

## 7. Hướng Dẫn Cấu Hình Môi Trường

### A. Khởi Động Google Chrome Với Remote Debugging
Trước khi thi đấu, mở Terminal chạy Chrome với cờ sau và đăng nhập tài khoản ChatGPT Web:
```bash
google-chrome --remote-debugging-port=9222 &
```

### B. Cài Đặt Oracle CLI
```bash
npm install -g @steipete/oracle
```
*Ghi chú: Nếu hệ thống chưa có Oracle, CLI `./ctf advisor` sẽ tự động kích hoạt chế độ Fallback (sao chép clipboard + thông báo người dùng) để không gián đoạn trận đấu.*

### C. Cấu Hình Cho OpenCode CLI (`~/.config/opencode/opencode.json`)
Để OpenCode tự động nhận diện kỹ năng `ctf-advisor` và PAL MCP:
```json
{
  "mcpServers": {
    "pal": {
      "command": "node",
      "args": ["/path/to/pal-mcp-server/dist/index.js"],
      "env": {
        "OPENAI_API_KEY": "...",
        "GEMINI_API_KEY": "..."
      }
    }
  }
}
```
OpenCode và Anti-IDE dùng chung cấu trúc thư mục `.advisor/` nên có thể hoán đổi hoặc chạy song song mà không xung đột trạng thái.
