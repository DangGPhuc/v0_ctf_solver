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
1. **Phase 1: Architecture Cleanup** *(Hoàn thành)*:
   - Khai tử workspace 4 tầng tĩnh tải trước toàn bộ bài thi.
   - Chuyển sang cơ chế nạp bài lười (Lazy Materialization) trong `.runtime/`.
2. **Phase 2: Core / Knowledge Separation** *(Hoàn thành)*:
   - Tách rời bộ não `v0_ctf_knowledge` khỏi engine `v0_ctf_solver`.
   - Giảm kích thước core từ > 10 MB xuống 1.9 MB; `.agents/skills` giảm từ 4.7 MB xuống 58 KB.
3. **Phase 3: Merge-Gate Hardening** *(Hoàn thành & Verified)*:
   - **Cách ly tuyệt đối**: `ContainerExecutor` chạy `--cap-drop=ALL`, `--network=none`, không bao giờ âm thầm chạy lại mã độc hại trên host.
   - **Typed Actions**: Cấm model chạy shell tự do; chỉ thực thi các `ExecutionAction` có cấu trúc.
   - **GitHub REST Contents API**: Truy cập repository private bằng xác thực `Bearer` và media `vnd.github.raw+json`.
   - **CI Xanh 100%**: Matrix Python 3.10, 3.12, 3.13 trên GitHub Actions.
4. **Phase 4: Solver Intelligence** *(Mục tiêu trọng tâm tiếp theo)*:
   - Chuyển trọng tâm từ "sửa đường ống" sang "nâng cao trí tuệ giải bài".
   - Chuẩn hóa: `Triage -> Deep Fingerprint -> Retrieval -> Hypothesis -> Experiment -> Evidence`.
5. **Phase 5: Adaptive Learning**:
   - Tối ưu hóa bộ lập lịch theo Kỳ Vọng Giá Trị (Expected Value).
   - Tự động gộp và tăng cường thẻ kỹ thuật thay vì tạo trùng lặp.
6. **Phase 6: Scaled Parallel Autonomy**:
   - Đa luồng giải bài song song với kiểm soát rate limit và chi phí token.

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
