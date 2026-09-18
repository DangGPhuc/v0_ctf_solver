from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class StateCapsule:
    """
    Viên nang trạng thái (State Capsule - chuẩn Prompt Master):
    Nén gọn toàn bộ dữ kiện đã kiểm chứng, các giả thuyết đã bị bác bỏ,
    tiến độ gần nhất và tri thức kinh nghiệm tương tự mà không gây ô nhiễm prompt.
    """

    challenge_id: str
    challenge_name: str
    category: str
    confirmed_facts: List[str] = field(default_factory=list)
    active_hypothesis: Optional[str] = None
    active_hypothesis_id: Optional[str] = None
    active_hypothesis_statement: Optional[str] = None
    rejected_hypotheses: List[Dict[str, str]] = field(default_factory=list)
    recent_progress: List[Dict[str, str]] = field(default_factory=list)
    unresolved_questions: List[str] = field(default_factory=list)
    retrieved_hints: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_markdown(self) -> str:
        sections = [f"### STATE CAPSULE: {self.challenge_name} (ID: {self.challenge_id} | {self.category.upper()})"]

        # 1. Confirmed Facts
        sections.append("#### 1. Confirmed Facts (Dữ kiện đã xác minh độc lập):")
        if self.confirmed_facts:
            for fact in self.confirmed_facts:
                sections.append(f"- {fact}")
        else:
            sections.append("- *Chưa có dữ kiện xác minh.*")

        # 2. Active Hypothesis
        active_display = self.active_hypothesis_statement or self.active_hypothesis or "Chưa xác định"
        if self.active_hypothesis_id and self.active_hypothesis_id not in active_display:
            active_display = f"[{self.active_hypothesis_id}] {active_display}"
        sections.append(f"\n#### 2. Active Hypothesis (Giả thuyết đang tập trung):\n- **{active_display}**")


        # 3. Rejected Hypotheses
        sections.append("\n#### 3. Rejected Hypotheses (Các hướng ĐÃ THỬ VÀ THẤT BẠI - TUYỆT ĐỐI KHÔNG LẶP LẠI):")
        if self.rejected_hypotheses:
            for rh in self.rejected_hypotheses:
                name = rh.get("name", "Unknown")
                reason = rh.get("reason", "Failed")
                sections.append(f"- ❌ **{name}**: {reason}")
        else:
            sections.append("- *Chưa ghi nhận hướng đi nào bị bác bỏ.*")

        # 4. Recent Progress
        sections.append("\n#### 4. Recent Progress (2-3 thực nghiệm gần nhất):")
        if self.recent_progress:
            for p in self.recent_progress:
                exp_id = p.get("id", "EXP")
                st = p.get("status", "UNKNOWN")
                act = p.get("actions", "")
                obs = p.get("observed", "")
                sections.append(f"- `[{exp_id} - {st}]` Hành động: {act} ➔ Ghi nhận: {obs}")
        else:
            sections.append("- *Chưa có lịch sử thực nghiệm.*")

        # 5. Retrieved Hints (Đóng dấu rõ là HINTS, không phải Fact)
        if self.retrieved_hints:
            sections.append("\n#### 5. Retrieved Experience Hints (Chỉ dẫn tham khảo từ bài tương tự - KHÔNG PHẢI FACT):")
            for h in self.retrieved_hints:
                chall = h.get("source", "Case")
                hint = h.get("hint", "")
                sections.append(f"- 💡 [Nguồn: {chall}]: {hint}")

        return "\n".join(sections)
