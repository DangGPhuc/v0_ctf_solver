# 🧠 V3 Solver Intelligence Specification & Architectural Roadmap

## 1. Triết Lý Kiến Trúc: Bốn Tầng Tách Bạch Tuyệt Đối

Hệ thống `v0_ctf_solver` đã hoàn thành quá trình tái cấu trúc từ mô hình nguyên khối (monolithic) sang mô hình động (ephemeral engine), thiết lập ranh giới bất biến giữa 4 lớp:

| Tầng | Định Nghĩa | Bản Chất | Vị Trí Lưu Trữ |
| :--- | :--- | :--- | :--- |
| **Skill** | **HOW** | Quy trình vận hành, phán đoán kỹ thuật, triage, điều kiện dừng | `.agents/skills/` (siêu nhẹ, < 100 KB) |
| **Knowledge** | **WHAT WE KNOW** | Bộ nhớ dài hạn: Thẻ kỹ thuật, writeup, tham chiếu, failure patterns | `DangGPhuc/v0_ctf_knowledge` (GitHub Contents API) |
| **Tool** | **WHAT WE EXECUTE WITH** | Công cụ thực thi (IDA Pro MCP, checksec, Ghidra, Sage, Z3) | `~/.local/share/v0_ctf_solver/tools/` (On-demand) |
| **Runtime** | **WHAT WE WORK ON** | Môi trường giải bài tạm thời (materialize theo yêu cầu, dọn sạch sau giải) | `.runtime/<event>/challenges/<id>/` (Ephemeral) |

---

## 2. Tiến Trình Phát Triển (6-Phase Evolutionary Roadmap)

```
V0: Kho script & notes nguyên khối (reverse-skill)
 │
 ▼
V1: Tự động hóa quy trình CTF (workspace tĩnh)
 │
 ▼
V2: Engine thực thi tinh gọn + Bộ nhớ dài hạn ngoại vi (Hiện tại - Đã xong Merge Gate)
 │
 ▼
V3: Solving Intelligence: Vòng lặp suy luận dựa trên bằng chứng (Đang tiến hành)
 │
 ▼
V4: Adaptive Learning: Học hỏi từ thất bại & tổng hợp tri thức tự động
 │
 ▼
V5: Scaled Autonomy: Đa tác tử song song với ngân sách tài nguyên (End-state)
```

### Chi tiết các giai đoạn:
1. **Phase 1: Evidence Evaluation Loop** *(Hoàn thành)*:
   - Chuẩn hóa vòng lặp suy luận: `Hypothesis -> Canonical Experiment -> ExecutionAction[] -> ExecutionResult -> Deterministic EvidenceEvaluator -> Hypothesis Update`.
   - Bảo toàn các bất biến: Lỗi thực thi/timeout luôn là `INCONCLUSIVE`, không bao giờ là bằng chứng bác bỏ giả thuyết; thiếu text trong output bị cắt ngắn không dẫn đến `REJECTED`.
2. **Phase 2: Experiment Candidate Generation & Selection** *(Hoàn thành - V3 Phase 2)*:
   - Phân tách `ExperimentCandidate` (đề xuất từ Advisor, tối đa 2-3 ứng viên, không sở hữu mã EXP) và `Experiment` (bản ghi chuẩn tắc do hệ thống sở hữu).
   - `ExperimentPlanner`: Bộ chọn thực nghiệm tất định theo thứ tự từ điển (Khả thi -> Trạng thái giả thuyết -> Ngăn chặn thử lại vô ích -> Bằng chứng mới -> Phân biệt giả thuyết -> Chi phí thấp làm tiêu chí phụ).
   - `SolverProgressTracker`: Theo dõi bằng chứng mới tất định và phát hiện bế tắc (Stagnation) khi N vòng không sinh bằng chứng mới.
   - **Đóng chốt các bất biến sản xuất (Production Invariants Hardening)**:
     - Atomic concurrency-safe canonical experiment allocation (`.advisor/.experiments.lock`).
     - Idempotent / atomic flag submission reservation (`.submitted_flags.lock` + `pending` state) chống submit trùng.
     - Bounded I/O: Giới hạn dung lượng tải về và stream capture (`MAX_STDOUT_BYTES`, `MAX_ATTACHMENT_BYTES`) với cờ `stdout_truncated`.
     - Chống tiêm mã (Injection-safe metadata): Toàn bộ thông tin bài thi (tên bài, host, port, metadata) được tuần tự hóa an toàn qua `json.dumps()` / schema structured JSON.
3. **Future Phase: Adaptive Scheduling / Tournament ROI / P(solve)** *(Chưa triển khai - Đang quy hoạch)*:
   - Đánh giá khả năng giải bài theo xác suất $P(\text{solve})$ và tỷ lệ hoàn vốn điểm số (Expected Value / ROI) cho toàn giải đấu.
4. **Future Phase: Autonomous Knowledge Distillation** *(Chưa triển khai)*:
   - Học hỏi từ thất bại & tổng hợp Thẻ Tri Thức tự động đẩy PR lên `v0_ctf_knowledge`.
5. **Future Phase: Parallel Multi-Worker Coordination** *(Chưa triển khai)*:
   - Phối hợp nhiều solver workers giải nhiều bài đồng thời có kiểm soát xung đột tài nguyên.

---

## 3. Kiến Trúc V3: Solving Intelligence Engine

### 3.1. Deep Challenge Fingerprint (`ChallengeFingerprint`)
Không còn dừng lại ở Category chung chung (`Pwn`, `Rev`, `Web`), hệ thống phân tích sâu dấu vân tay bài thi:

```python
class ChallengeFingerprint(BaseModel):
    category: str                                  # pwn, rev, web, crypto, forensics, etc.
    subcategory: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    file_types: List[str] = Field(default_factory=list)      # elf, pe, wasm, pcap, archive, etc.
    architectures: List[str] = Field(default_factory=list)   # x86-64, arm-cortex-m, mips, riscv
    frameworks: List[str] = Field(default_factory=list)      # zephyr, node, flask, django, spring
    protections: List[str] = Field(default_factory=list)     # nx, no-pie, no-canary, full-relro
    primitives: List[str] = Field(default_factory=list)      # stack-overflow, format-string, uaf, sqli
    suspicious_patterns: List[str] = Field(default_factory=list)
    runtime_signals: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = 0.5
```

### 3.2. Vòng Lặp Thực Nghiệm Dựa Trên Bằng Chứng (Evidence-Driven Loop)
Thay vì để mô hình viết code khai thác ngay từ đầu, hệ thống ép buộc quy trình suy luận khoa học:

```text
Fingerprint
    ↓
Knowledge Context
    ↓
Advisor
    ↓
Hypothesis
    ↓
Experiment
    ↓
Typed Execution
    ↓
Evidence
    ↓
Evaluation
├── Confirm
├── Reject
└── Inconclusive
    ↓
Pivot
```

### 3.3. Ranh Giới Trách Nhiệm Tách Bạch Tuyệt Đối (Phase 1 Invariants)
- **Advisor**: Đề xuất giả thuyết (`Hypothesis`) và thực nghiệm kiểm chứng (`Experiment`). KHÔNG trực tiếp thực thi tool hay quyết định tính chân lý của giả thuyết.
- **HypothesisManager**: Theo dõi vòng đời lý luận (`proposed -> active -> confirmed / rejected / inconclusive`). KHÔNG chạy tool, KHÔNG gọi platform, KHÔNG gọi LLM.
- **ExperimentLedger**: Nguồn ghi chép duy nhất (Single Canonical Writer) cho toàn bộ lịch sử thực nghiệm (`.advisor/experiments.jsonl`). Tự phục hồi khi gặp dòng lỗi.
- **Executor (RestrictedLocal / Container)**: Thực thi các hành động định kiểu an toàn (`ExecutionAction`). KHÔNG quyết định kết quả giả thuyết.
- **EvidenceEvaluator**: Đánh giá kết quả thực nghiệm hoàn toàn tất định (Deterministic, NO LLM). Execution failure/timeout dẫn tới `INCONCLUSIVE`, tuyệt đối KHÔNG ngộ nhận thành `REJECTED`.
- **DiscoveryTree**: Trực quan hóa cây không gian tìm kiếm (DAG Exploration Visualization).

### 3.4. Hợp Đồng Dữ Liệu `Hypothesis` & `Experiment`
```python
class Hypothesis(BaseModel):
    id: str = "H1"
    statement: str
    confidence: float = 0.5
    rationale: str = ""
    status: Literal["proposed", "active", "confirmed", "rejected", "inconclusive"] = "proposed"
    attempts: int = 0
    failure_count: int = 0
    supporting_evidence: List[str] = Field(default_factory=list)
    contradicting_evidence: List[str] = Field(default_factory=list)

class Experiment(BaseModel):
    experiment_id: str
    hypothesis_id: str
    intent: str
    action: Optional[ExecutionAction] = None
    execution_plan: List[ExecutionAction] = Field(default_factory=list)
    expected_evidence: List[str] = Field(default_factory=list)
    contradicting_evidence: List[str] = Field(default_factory=list)
    actual_evidence: List[str] = Field(default_factory=list)
    outcome: Literal["pending", "confirmed", "rejected", "inconclusive", "failed", "flag_found"] = "pending"
    reason: str = ""
```

---

## 4. Bộ Lập Lịch Tối Ưu Hóa (ROI-Driven Scheduler)

Thay thế chiến lược đơn giản `lowest points first` bằng công thức Tối Đa Hóa Kỳ Vọng Điểm Số (Expected Value - EV):

$$\text{Expected Value (EV)} = \frac{P(\text{solve}) \times \text{points}}{\text{estimated\_time\_minutes}}$$

Trong đó:
* $P(\text{solve})$ được tính toán từ:
  1. Trọng số kỹ năng lịch sử của hệ thống theo category.
  2. Điểm tương đồng giữa `ChallengeFingerprint` với Thẻ Tri Thức có sẵn trong `v0_ctf_knowledge`.
* Nếu bài thi khớp chính xác với một Thẻ Kỹ Thuật chất lượng cao đã kiểm chứng: $P(\text{solve}) \approx 0.85$.
* Nếu bài thi 500 điểm nhưng thuộc mảng chưa có mẫu kỹ thuật và đòi hỏi thời gian lớn: $EV$ giảm thấp, nhường tài nguyên cho các bài có ROI cao hơn.

---

## 5. Tự Động Hóa Học Hỏi & Chắt Lọc Tri Thức (Knowledge Synthesis)

Sau khi giải thành công một bài thi:
1. `DiscoveryTree` trích xuất **Winning Path** (nhánh thực nghiệm dẫn tới flag).
2. Tạo Thẻ Tri Thức ứng viên trong `~/.local/state/v0_ctf_solver/knowledge-outbox/`.
3. Kiểm tra tính trùng lặp:
   * Nếu kỹ thuật đã tồn tại (ví dụ: `web.path-traversal.user-controlled-path`): bổ sung thêm trường hợp mới (Node.js, Python, Go) thay vì tạo thẻ rác.
   * Nếu kỹ thuật mới: tạo nhánh `knowledge/candidate-<slug>` và mở PR an toàn lên `v0_ctf_knowledge`.

---

## 6. Vòng Đời Tác Chiến Giải Đấu & Tiêu Hủy Tự Động (Tournament Lifecycle & Zero-Bloat Teardown)

### 6.1. Ranh Giới Thực Thi: Anti-IDE & OpenCode
- **Anti-IDE** và **OpenCode** giữ vai trò **Executors**: Chịu trách nhiệm trực tiếp tương tác hệ thống tệp, chạy subprocess / sandbox container, tương tác công cụ phân tích tĩnh/động (IDA Pro MCP, GDB), và nộp cờ tự động.
- **Strategic Advisor (ChatGPT Web)**: Giữ vai trò Cố vấn chiến lược độc lập, ban hành `ExecutionProposal` và phản biện bế tắc giả định.

### 6.2. Quy Trình Vận Hành Giải Đấu Tự Động
1. **Khởi tạo Workspace**: Với mỗi giải CTF mới, tạo thư mục mang tên giải đấu trong repo (`mkdir <tournament_name> && cd <tournament_name>`).
2. **Nạp Credentials**: Cung cấp refresh token / API token / session cookie cho Agent bằng lệnh:
   `ctf env set -u "<URL>" -t "<TOKEN>" -c "<COOKIE>"`
3. **Kích hoạt Chu Trình Tự Động**: Chạy `ctf auto` để Anti-IDE và OpenCode tự động đồng bộ bài, nạp bài lười, suy luận giả thuyết và giải bài khép kín.

### 6.3. Sàng Lọc Tri Thức & Tiêu Hủy Hoàn Toàn Cuối Giải
Khi giải đấu kết thúc:
1. **Chắt lọc tri thức (Knowledge Distillation)**: Anti-IDE quét toàn bộ cây khám phá và lịch sử thực nghiệm, trích xuất Winning Paths, kỹ thuật mới, và anti-patterns, đóng gói thành Thẻ Tri Thức và đẩy lên `DangGPhuc/v0_ctf_knowledge`.
2. **Tiêu hủy hoàn toàn không để lại rác**:
   - Dọn sạch toàn bộ file nhị phân đính kèm, logs, file tạm, scratchpad solver.
   - **Xóa bỏ hoàn toàn chính thư mục giải đấu `<tournament_name>/`** (`rm -rf <tournament_name>`).
   - Đảm bảo repo `v0_ctf_solver` luôn giữ nguyên tắc **Zero Permanent Event Bloat**.
