import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional
import yaml


@dataclass
class ExplorationPolicy:
    """
    Quy định chính sách tác chiến (Procedural Memory) điều khiển cách 2 Agent phối hợp,
    khám phá không gian tìm kiếm, cắt tỉa nhánh chết và điều kiện dừng.
    """

    version: str = "1.0.0"
    name: str = "conservative_dual_agent"
    description: str = "Chính sách tác chiến thận trọng chuẩn: Ngân sách 2 fail, hỏi Advisor khi khởi đầu và bế tắc."

    # Tham số khám phá
    branching: Dict[str, Any] = field(default_factory=lambda: {
        "initial_hypotheses": 2,      # Số lượng giả thuyết H1, H2 cố vấn đề xuất
        "parallel_branches": 1,       # Số nhánh Executor thử nghiệm đồng thời
        "prune_dead_ends": True,      # Cắt tỉa nhánh khi nhận kết quả REJECTED
    })

    # Tham số cố vấn (Advisor)
    advisor: Dict[str, Any] = field(default_factory=lambda: {
        "ask_at_start": True,
        "review_after_failed_attempts": 2,
        "review_before_major_pivot": True,
        "escalate_after_stalled_rounds": 2,
    })

    # Tham số thực thi (Executor)
    executor: Dict[str, Any] = field(default_factory=lambda: {
        "require_evidence": True,
        "max_raw_log_lines": 40,
        "require_reproduction": True,
        "command_timeout_seconds": 60,
    })

    # Điều kiện dừng
    stopping: Dict[str, Any] = field(default_factory=lambda: {
        "max_consecutive_failures": 2,
        "max_total_consultations": 10,
        "kill_duplicate_branch": True,
    })

    # Trọng số tính điểm Replay Benchmark (theo Dream-RSI)
    scoring: Dict[str, Any] = field(default_factory=lambda: {
        "flag_reward": 10000,
        "cost_per_executor_action": -10,
        "cost_per_advisor_call": -30,
        "cost_per_minute": -5,
        "penalty_dead_branch": -20,
    })

    # Cấu hình Prompt Engine (theo Prompt Master)
    prompt_policy: Dict[str, Any] = field(default_factory=lambda: {
        "recent_nodes_depth": 4,
        "retrieved_cases_limit": 1,
        "strict_linter": True,
        "evidence_detail_level": "compact",
        "executor_template": "template_h_react",
        "advisor_template": "template_e_auditable",
    })

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExplorationPolicy":
        return cls(**data)

    @classmethod
    def load_from_file(cls, filepath: Path) -> "ExplorationPolicy":
        filepath = Path(filepath)
        if not filepath.is_file():
            raise FileNotFoundError(f"Không tìm thấy file policy: {filepath}")
        content = filepath.read_text(encoding="utf-8")
        data = yaml.safe_load(content) or {}
        return cls.from_dict(data)

    def save(self, filepath: Path):
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        data = self.to_dict()
        filepath.write_text(yaml.dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")

    @classmethod
    def get_default(cls) -> "ExplorationPolicy":
        return cls()

    @classmethod
    def load_active_policy(cls, policies_dir: Optional[Path] = None) -> "ExplorationPolicy":
        """
        Nạp chính sách đang kích hoạt:
        Ưu tiên policies/current.yaml, nếu không có thì trả về default.
        """
        if policies_dir:
            p_file = Path(policies_dir) / "current.yaml"
            if p_file.is_file():
                return cls.load_from_file(p_file)

        # Tìm theo vị trí mặc định của project
        default_current = Path(__file__).resolve().parents[2] / "policies" / "current.yaml"
        if default_current.is_file():
            return cls.load_from_file(default_current)

        return cls.get_default()
