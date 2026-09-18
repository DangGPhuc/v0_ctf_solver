from dataclasses import dataclass
from typing import List, Optional, Tuple

from .spec import PromptSpec


@dataclass
class LintViolation:
    """Đại diện cho một vi phạm anti-pattern trong prompt."""
    code: str
    severity: str  # ERROR, WARNING
    message: str
    auto_repaired: bool = False

    @property
    def rule_id(self) -> str:
        return self.code

    @property
    def description(self) -> str:
        return self.message

    @property
    def auto_fixed(self) -> Optional[str]:
        return "✔ Đã tự động vá" if self.auto_repaired else None


class PromptLinter:
    """
    Bộ kiểm chuẩn Prompt (Prompt Linter - chuẩn Prompt Master):
    Quét tự động các anti-patterns làm giảm hiệu năng, gây ảo giác hoặc lãng phí tài nguyên
    của AI Agent, đồng thời tự động sửa chữa (Auto-Repair) trước khi phát hành prompt.
    """

    DEFAULT_STOP_CONDITIONS = [
        "Dừng ngay khi hypothesis được CONFIRMED hoặc REJECTED",
        "Dừng nếu sau 2 lần thử nghiệm liên tiếp không thu được bất kỳ evidence mới nào",
        "Dừng nếu phát hiện flag hoặc solver bắt được cờ",
    ]

    DEFAULT_FORBIDDEN_SCOPE = [
        "TUYỆT ĐỐI KHÔNG lặp lại các giả thuyết đã bị Rejected",
        "TUYỆT ĐỐI KHÔNG tự ý rời khỏi mục tiêu giả thuyết được giao",
    ]

    DEFAULT_EVIDENCE_CONTRACT = [
        "Mọi kết luận phải trích dẫn lệnh/tool đã chạy",
        "Mọi quan sát phải có dữ liệu thực tế (registers, response, error trace)",
        "Không dump toàn bộ log thô, chỉ gửi bằng chứng then chốt",
    ]

    @classmethod
    def lint(cls, spec: PromptSpec) -> List[LintViolation]:
        """Quét và liệt kê tất cả các vi phạm anti-pattern của PromptSpec."""
        violations: List[LintViolation] = []

        # 1. Kiểm tra Điều kiện dừng (Stop Conditions)
        if not spec.stop_conditions or len(spec.stop_conditions) == 0:
            violations.append(LintViolation(
                code="NO_STOP_CONDITIONS",
                severity="ERROR",
                message="Prompt thiếu điều kiện dừng (Stop Conditions), có nguy cơ làm Agent chạy vòng lặp vô hạn.",
            ))

        # 2. Kiểm tra Ranh giới phạm vi (Scope Boundaries)
        if not spec.allowed_scope or len(spec.allowed_scope) == 0:
            violations.append(LintViolation(
                code="NO_ALLOWED_SCOPE",
                severity="WARNING",
                message="Prompt không quy định Allowed Scope, Agent có thể gọi tool không cần thiết.",
            ))

        if not spec.forbidden_scope or len(spec.forbidden_scope) == 0:
            violations.append(LintViolation(
                code="NO_FORBIDDEN_SCOPE",
                severity="ERROR",
                message="Prompt thiếu Forbidden Scope, Agent có thể thử lại các hướng đã thất bại.",
            ))

        # 3. Kiểm tra Tiêu chí thành công (Success Criteria)
        if not spec.success_criteria or len(spec.success_criteria) == 0:
            violations.append(LintViolation(
                code="NO_SUCCESS_CRITERIA",
                severity="ERROR",
                message="Prompt thiếu tiêu chí nghiệm thu kết quả rõ ràng.",
            ))

        # 4. Kiểm tra Hợp đồng bằng chứng (Evidence Contract)
        if not spec.evidence_contract or len(spec.evidence_contract) == 0:
            violations.append(LintViolation(
                code="NO_EVIDENCE_CONTRACT",
                severity="WARNING",
                message="Prompt không yêu cầu trích dẫn bằng chứng cụ thể, Agent dễ đưa ra kết luận vô căn cứ.",
            ))

        # 5. Kiểm tra State Capsule
        if not spec.state_capsule:
            violations.append(LintViolation(
                code="NO_STATE_CAPSULE",
                severity="ERROR",
                message="Prompt thiếu State Capsule nền tảng, Agent mất liên kết với các dữ kiện đã xác minh.",
            ))
        else:
            # Kiểm tra xem có đang yêu cầu kiểm tra lại giả thuyết đã bị rejected không
            active = (spec.state_capsule.active_hypothesis or "").lower()
            obj = (spec.task_objective or "").lower()
            for rh in spec.state_capsule.rejected_hypotheses:
                r_name = rh.get("name", "").lower()
                if r_name and (r_name in active or r_name in obj):
                    violations.append(LintViolation(
                        code="TARGETING_REJECTED_HYPOTHESIS",
                        severity="ERROR",
                        message=f"Giả thuyết/mục tiêu ({r_name}) trùng với hướng đã bị Bác Bỏ!",
                    ))

        return violations

    @classmethod
    def lint_and_repair(cls, spec: PromptSpec) -> Tuple[PromptSpec, List[LintViolation]]:
        """Quét vi phạm và tự động sửa chữa (Auto-Repair) các thiếu sót nghiêm trọng."""
        violations = cls.lint(spec)

        for v in violations:
            if v.code == "NO_STOP_CONDITIONS":
                spec.stop_conditions = list(cls.DEFAULT_STOP_CONDITIONS)
                v.auto_repaired = True
            elif v.code == "NO_FORBIDDEN_SCOPE":
                spec.forbidden_scope = list(cls.DEFAULT_FORBIDDEN_SCOPE)
                v.auto_repaired = True
            elif v.code == "NO_ALLOWED_SCOPE":
                spec.allowed_scope = ["Chỉ làm việc trong workspace của challenge", "Được phép chạy phân tích tĩnh/động"]
                v.auto_repaired = True
            elif v.code == "NO_SUCCESS_CRITERIA":
                spec.success_criteria = ["Trả về kết luận: CONFIRMED, REJECTED, hoặc INCONCLUSIVE kèm bằng chứng"]
                v.auto_repaired = True
            elif v.code == "NO_EVIDENCE_CONTRACT":
                spec.evidence_contract = list(cls.DEFAULT_EVIDENCE_CONTRACT)
                v.auto_repaired = True

        return spec, violations
