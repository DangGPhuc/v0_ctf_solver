from typing import Any, Dict

from .spec import PromptSpec


class CTFTemplates:
    """
    Hệ thống mẫu Prompt hợp đồng (Contract Templates - chuẩn Prompt Master):
    - Template H: ReAct + Stop Conditions dành cho Executor (Anti-IDE / OpenCode)
    - Template E: Auditable Reasoning dành cho Advisor (ChatGPT Web)
    """

    @classmethod
    def render_executor_contract(cls, spec: PromptSpec) -> str:
        """
        Template H: ReAct + Agentic Stop Conditions
        Giao nhiệm vụ thực nghiệm cho Executor một cách chặt chẽ và an toàn.
        """
        capsule_md = spec.state_capsule.to_markdown()

        allowed_lines = "\n".join([f"- {a}" for a in spec.allowed_scope])
        forbidden_lines = "\n".join([f"- {f}" for f in spec.forbidden_scope])
        stop_lines = "\n".join([f"- {s}" for s in spec.stop_conditions])
        criteria_lines = "\n".join([f"- {c}" for c in spec.success_criteria])
        evidence_lines = "\n".join([f"- {e}" for e in spec.evidence_contract])

        artifacts_block = ""
        if spec.context_artifacts:
            art_lines = []
            for k, v in spec.context_artifacts.items():
                if v:
                    art_lines.append(f"### {k.upper()}:\n{v}")
            if art_lines:
                artifacts_block = "\n\n## 7. ATTACHED CONTEXT & ARTIFACTS\n" + "\n\n".join(art_lines)

        return (
            f"# EXECUTOR TASK CONTRACT (Template H: ReAct + Stop Conditions)\n\n"
            f"## 1. OBJECTIVE (Mục tiêu thực nghiệm)\n"
            f"{spec.task_objective}\n\n"
            f"## 2. STARTING STATE (Viên nang trạng thái đã xác minh)\n"
            f"{capsule_md}\n\n"
            f"## 3. SCOPE BOUNDARIES (Ranh giới phạm vi được phép)\n"
            f"### ALLOWED ACTIONS:\n{allowed_lines}\n\n"
            f"### FORBIDDEN ACTIONS (CẤM):\n{forbidden_lines}\n\n"
            f"## 4. AGENTIC STOP CONDITIONS (Điều kiện dừng ngay lập tức)\n"
            f"{stop_lines}\n\n"
            f"## 5. EVIDENCE CONTRACT (Ràng buộc bằng chứng tối thiểu)\n"
            f"{evidence_lines}\n\n"
            f"## 6. SUCCESS CRITERIA (Tiêu chí nghiệm thu)\n"
            f"{criteria_lines}\n\n"
            f"## 7. MANDATORY RETURN FORMAT (Cấu trúc báo cáo bắt buộc)\n"
            f"Khi hoàn thành hoặc khi chạm Stop Condition, trả về theo cấu trúc:\n"
            f"```yaml\n"
            f"status: CONFIRMED | REJECTED | INCONCLUSIVE\n"
            f"actions_executed: \"<lệnh đã chạy>\"\n"
            f"observed_evidence: \"<dữ liệu thanh ghi, leak, error trích lọc>\"\n"
            f"analysis_diff: \"<so sánh thực tế vs kỳ vọng>\"\n"
            f"new_facts: [\"<dữ kiện mới nếu có>\"]\n"
            f"open_questions: [\"<câu hỏi cần cố vấn trả lời>\"]\n"
            f"```"
            f"{artifacts_block}\n"
        )

    @classmethod
    def render_advisor_contract(cls, spec: PromptSpec) -> str:
        """
        Template E: Auditable Reasoning Protocol
        Ép ChatGPT Web trở thành Lead Strategic Advisor có tư duy phản biện và kiểm chứng.
        """
        capsule_md = spec.state_capsule.to_markdown()

        artifacts_block = ""
        if spec.context_artifacts:
            art_lines = []
            for k, v in spec.context_artifacts.items():
                if v:
                    art_lines.append(f"### {k.upper()}:\n{v}")
            if art_lines:
                artifacts_block = "\n\n## 3. ATTACHED CONTEXT & ARTIFACTS\n" + "\n\n".join(art_lines)

        return (
            f"# STRATEGIC ADVISOR DIRECTIVE (Template E: Auditable Reasoning)\n\n"
            f"Bạn là **Lead Strategic Advisor** cho Đội tuyển thi đấu CTF.\n"
            f"Đối tác của bạn là **Executor Agent** đang có mặt trực tiếp tại môi trường challenge.\n\n"
            f"## 1. MỤC TIÊU PHÂN TÍCH HIỆN TẠI\n"
            f"{spec.task_objective}\n\n"
            f"## 2. VIÊN NANG TRẠNG THÁI HIỆN TẠI (State Capsule)\n"
            f"{capsule_md}"
            f"{artifacts_block}\n\n"
            f"## 4. NGUYÊN TẮC CHIẾN LƯỢC CHO CỐ VẤN\n"
            f"1. **Không lý thuyết lan man**: Đi thẳng vào cấu trúc bộ nhớ, toán học rút gọn hoặc logic lỗ hổng.\n"
            f"2. **Auditable Reasoning**: Mọi giả thuyết đề xuất phải nêu rõ giả định (Assumptions) và bằng chứng ủng hộ/phản đối.\n"
            f"3. **Prune Dead-Ends**: Chủ động yêu cầu Executor dừng hoặc cắt tỉa các nhánh không còn tiềm năng.\n\n"
            f"## 5. CẤU TRÚC PHẢN HỒI BẮT BUỘC (Auditable Output Contract)\n"
            f"Hãy trả lời chính xác theo 6 phần sau:\n\n"
            f"### 1. ASSESSMENT & STATUS\n"
            f"- Tóm tắt đánh giá ngắn gọn về bài toán dựa trên các dữ kiện vừa nhận.\n\n"
            f"### 2. RANKED HYPOTHESES\n"
            f"- **H1 (Primary)**: [Giả thuyết hàng đầu] - Cơ chế khai thác khả dĩ nhất.\n"
            f"- **H2 (Alternative)**: [Giả thuyết dự phòng] - Nếu H1 sai thì thử hướng này.\n\n"
            f"### 3. ASSUMPTIONS & UNCERTAINTY\n"
            f"- Giả định nào cần phải đúng để H1 hoạt động? Còn thông tin nào đang thiếu?\n\n"
            f"### 4. SUPPORTING & CONTRADICTING EVIDENCE\n"
            f"- Bằng chứng nào trong State Capsule ủng hộ H1? Bằng chứng nào phản bác?\n\n"
            f"### 5. NEXT ACTIONS FOR EXECUTOR\n"
            f"- Lệnh chính xác Executor cần chạy (breakpoint GDB, micro-PoC Python, offsets).\n\n"
            f"### 6. STOP CONDITIONS & BRANCHES TO PRUNE\n"
            f"- Điều kiện Executor phải dừng lại báo cáo.\n"
            f"- Nhánh nào cần hủy bỏ ngay lập tức để tiết kiệm tài nguyên.\n\n"
            f"## 6. MACHINE-READABLE EXECUTION PLAN (MANDATORY JSON BLOCK)\n"
            f"Cuối phản hồi, BẮT BUỘC đính kèm khối JSON định kiểu (Typed Execution Plan & Experiment Proposal) để Executor tự động thực thi trong sandbox:\n"
            f"```json\n"
            f"{{\n"
            f'  "assessment": "<short assessment>",\n'
            f'  "hypotheses": [\n'
            f'    {{"id": "H1", "statement": "<testable claim>", "confidence": 0.8, "rationale": "<why>"}},\n'
            f'    {{"id": "H2", "statement": "<alternative>", "confidence": 0.5, "rationale": "<why>"}}\n'
            f'  ],\n'
            f'  "experiment_candidates": [\n'
            f'    {{\n'
            f'      "hypothesis_id": "H1",\n'
            f'      "intent": "<what this experiment tests>",\n'
            f'      "expected_evidence": ["<observation that supports H1>"],\n'
            f'      "contradicting_evidence": ["<observation that contradicts H1>"],\n'
            f'      "execution_plan": [\n'
            f'        {{"kind": "analysis_tool", "tool": "checksec", "argv": ["checksec", "--file=input:vuln"], "timeout": 20}}\n'
            f'      ],\n'
            f'      "estimated_cost_class": "low"\n'
            f'    }}\n'
            f'  ],\n'
            f'  "stop_conditions": [\n'
            f'    "<when executor should stop>"\n'
            f'  ]\n'
            f"}}\n"
            f"```\n"
            f"System Capabilities & Constraints:\n"
            f"- Supported action kinds: run_solver, run_python_file, run_sage_file, run_binary, analysis_tool, read_file, list_files.\n"
            f"- Allowed analysis tools: file, strings, readelf, objdump, checksec, nm, ltrace, strace, ropper, seccomp-tools.\n"
            f"- Single 'experiment' or up to 3 'experiment_candidates' may be proposed.\n"
            f"- Arbitrary shell commands, unapproved tools, and host path escapes are rejected.\n"
        )

