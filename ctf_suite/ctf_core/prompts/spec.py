from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from .state_capsule import StateCapsule


@dataclass
class PromptSpec:
    """
    Quy chuẩn ý định 9 chiều (9-Dimensional Intent Specification - chuẩn Prompt Master):
    Chuyển giao mục tiêu tác chiến thành một Hợp Đồng Giao Việc (Execution Contract) hoàn chỉnh,
    loại bỏ hoàn toàn việc Agent phải tự đoán phạm vi, công cụ hay điều kiện dừng.
    """

    task_objective: str
    state_capsule: StateCapsule
    task_type: str = "triage"  # triage, hypothesis_testing, exploit_dev, escalation, verification
    target_agent: str = "advisor"  # advisor, executor
    target_backend: str = "chatgpt"  # chatgpt, antigravity, opencode
    context_artifacts: Dict[str, Any] = field(default_factory=dict)

    # Phạm vi tác chiến (Scope Boundaries)
    allowed_scope: List[str] = field(default_factory=lambda: [
        "Chỉ làm việc trong thư mục challenge được phân công",
        "Sử dụng các công cụ phân tích tĩnh/động được phép (gdb, pwntools, ida_mcp, python, curl)",
        "Tạo script nháp trong thư mục script/",
    ])
    forbidden_scope: List[str] = field(default_factory=lambda: [
        "TUYỆT ĐỐI KHÔNG lặp lại các giả thuyết đã bị Rejected trừ khi có evidence mới",
        "TUYỆT ĐỐI KHÔNG bịa đặt hoặc phỏng đoán kết quả thực nghiệm chưa được quan sát",
        "TUYỆT ĐỐI KHÔNG tự ý rời khỏi mục tiêu giả thuyết hiện tại",
    ])

    # Điều kiện dừng (Agentic Stop Conditions)
    stop_conditions: List[str] = field(default_factory=lambda: [
        "Dừng ngay khi giả thuyết được Xác Nhận (CONFIRMED) hoặc Bác Bỏ (REJECTED)",
        "Dừng nếu sau 2 lần thử nghiệm liên tiếp không thu được bất kỳ evidence mới nào",
        "Dừng nếu phát hiện flag khớp format hoặc solver bắt được cờ",
        "Dừng nếu bước tiếp theo đòi hỏi vượt quá phạm vi được giao",
    ])

    # Tiêu chí thành công (Success Criteria)
    success_criteria: List[str] = field(default_factory=lambda: [
        "Đưa ra kết luận dứt khoát: CONFIRMED, REJECTED, hoặc INCONCLUSIVE",
        "Đính kèm đầy đủ bằng chứng kiểm chứng (lệnh đã chạy, offset, dump registers)",
    ])

    # Hợp đồng bằng chứng (Evidence Contract)
    evidence_contract: List[str] = field(default_factory=lambda: [
        "Mọi kết luận phải trích dẫn lệnh/tool đã chạy",
        "Mọi quan sát phải có dữ liệu thực tế (registers, response snippet, error trace)",
        "Không dump toàn bộ log terminal, chỉ gửi phần dữ liệu bằng chứng then chốt",
    ])

    # Định dạng đầu ra bắt buộc
    output_schema: str = "structured_contract"
    budget_remaining: Dict[str, Any] = field(default_factory=lambda: {"failures_remaining": 2, "consultations_remaining": 8})

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["state_capsule"] = self.state_capsule.to_dict()
        return data
