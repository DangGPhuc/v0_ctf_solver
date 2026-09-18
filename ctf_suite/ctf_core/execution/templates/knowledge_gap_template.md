# 🧬 KNOWLEDGE GAP & POST-MORTEM REPORT: {challenge_name}

- **Challenge**: `{challenge_name}`
- **Category**: `{category_upper}`
- **Date Created**: `{date}`
- **Target Target/Binary**: `{target_repr}`
- **Status**: ⚠️ DEADLOCK / DIAGNOSTIC MODE (Human-in-the-Loop Active)

---

## 1. Bản chất Lỗ hổng & Điểm nghẽn Cốt lõi (The Blocker)
* **Category & Sub-genre**: {subgenre}
* **Loại điểm nghẽn (Blocker Classification)**:
  - {blocker_env} *Environment Blocker*: Bị WAF rate-limit, Socket reset, Network jitter làm nhiễu, Anti-Bot.
  - {blocker_math} *Math / Complexity Explosion*: Độ phức tạp vượt quá $2^{24}$, Z3 solver timeout, ma trận chưa tối ưu LLL/BKZ.
  - {blocker_primitive} *Novel Primitive / Missing Gadget*: Cơ chế khai thác mới (V8 JIT, eBPF, Custom VM, Zero-day primitive) chưa có playbook hoặc thiếu toolchain tương thích.
* **Mô tả hiện tượng kẹt**: 
  {description}

---

## 2. Các câu hỏi kỹ thuật còn thiếu (Open Technical Inquiries)
*(Dành cho người dùng đọc để tìm kiếm tài liệu, CVE, hoặc writeup tương đương)*
* **Question 1**: {q1}
* **Question 2**: {q2}
* **Question 3**: {q3}

---

## 3. Kỹ thuật Phá giải (The Breakthrough - Cập nhật sau khi giải được)
* **Kỹ thuật mấu chốt**: {breakthrough_technique}
* **Mã khai thác / Hàm Helper bổ trợ**:
```python
# Insert core exploit snippet or helper function here
```

---

## 4. Đề xuất Tích hợp Vĩnh viễn vào Workspace (Self-Evolution Plan)
* **Playbook mới**: `skills/{category_lower}/{technique_name}.md`
* **Router Signature**: Thêm vào `skills/MASTER-ROUTING.md`
* **Field Journal Entry**: `skills/field-journal/{date}_{challenge_name}.md`
