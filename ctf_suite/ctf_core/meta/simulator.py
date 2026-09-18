from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .policy import ExplorationPolicy
from .tree import DiscoveryNode, DiscoveryTree


@dataclass
class ReplayResult:
    """Kết quả chạy mô phỏng Replay một ExplorationPolicy trên DiscoveryTree."""
    challenge_id: str
    policy_name: str
    policy_version: str
    success: bool
    flag_found: bool
    status: str  # SOLVED, UNKNOWN_BRANCH, STOPPED_BUDGET_EXCEEDED, FAILED
    steps_taken: int
    advisor_calls: int
    executor_actions: int
    dead_branches_pruned: int
    score: float
    path_taken: List[str] = field(default_factory=list)
    notes: str = ""


class ReplaySimulator:
    """
    Bộ mô phỏng Replay Simulator (chuẩn Dream-RSI):
    Thực thi một ứng viên ExplorationPolicy trên không gian tìm kiếm đã khám phá (DiscoveryTree)
    của các bài thi trong quá khứ mà KHÔNG cần chạy lại binary hay gọi lại LLM.
    """

    def __init__(self, policy: Optional[ExplorationPolicy] = None):
        self.policy = policy or ExplorationPolicy.get_default()

    def simulate(self, tree: DiscoveryTree, candidate_policy: Optional[ExplorationPolicy] = None) -> ReplayResult:
        policy = candidate_policy or self.policy
        scoring = policy.scoring

        # Kiểm tra xem cây có winning path không
        original_winning_path = tree.get_winning_path()
        has_flag_in_tree = original_winning_path is not None

        # Bắt đầu duyệt từ Root
        curr_node = tree.nodes.get(tree.root_id)
        if not curr_node:
            return ReplayResult(
                challenge_id=tree.challenge_id,
                policy_name=policy.name,
                policy_version=policy.version,
                success=False,
                flag_found=False,
                status="FAILED",
                steps_taken=0,
                advisor_calls=0,
                executor_actions=0,
                dead_branches_pruned=0,
                score=0.0,
                notes="Cây khám phá rỗng hoặc không có nút Root.",
            )

        steps = 0
        advisor_calls = 0
        executor_actions = 0
        dead_branches = 0
        consecutive_failures = 0
        path_taken = [curr_node.node_id]

        queue: List[DiscoveryNode] = [curr_node]
        visited = set([curr_node.node_id])
        flag_reached = False
        reached_node = None
        status = "IN_PROGRESS"

        max_failures = policy.stopping.get("max_consecutive_failures", 2)
        prune_dead_ends = policy.branching.get("prune_dead_ends", True)

        while queue:
            node = queue.pop(0)
            steps += 1

            if node.node_type == "advisor_consultation" or node.actor == "advisor":
                advisor_calls += 1
            elif node.node_type == "action" or node.actor == "executor":
                executor_actions += 1

            if node.node_type == "terminal_flag" or node.status == "solved":
                flag_reached = True
                reached_node = node
                status = "SOLVED"
                break

            # Đánh giá kết quả nút
            if node.status == "rejected":
                consecutive_failures += 1
                dead_branches += 1

                # Kiểm tra xem có nhánh escalation nào được sinh ra từ nút bế tắc này không
                children = tree.get_children(node.node_id)
                escalation_nodes = [c for c in children if c.node_type == "escalation" or "escalat" in c.node_type]

                if escalation_nodes and policy.advisor.get("escalate_after_stalled_rounds", 2):
                    consecutive_failures = 0
                    for esc in escalation_nodes:
                        if esc.node_id not in visited:
                            visited.add(esc.node_id)
                            queue.append(esc)
                            path_taken.append(esc.node_id)
                    continue

                if consecutive_failures >= max_failures:
                    status = "STOPPED_BUDGET_EXCEEDED"
                    break

                if prune_dead_ends:
                    continue
            elif node.status == "confirmed":
                consecutive_failures = 0

            # Lấy các nhánh con tiếp theo
            children = tree.get_children(node.node_id)
            if not children:
                continue

            # Ưu tiên duyệt các nhánh chưa bị pruned
            valid_children = [c for c in children if c.status != "pruned"]
            if not valid_children:
                continue

            # Sắp xếp nhánh: ưu tiên nhánh có kết quả confirmed/solved trước
            valid_children.sort(key=lambda c: 0 if c.status in ["confirmed", "solved"] else 1)

            for child in valid_children:
                if child.node_id not in visited:
                    visited.add(child.node_id)
                    queue.append(child)
                    path_taken.append(child.node_id)

        if not flag_reached and status == "IN_PROGRESS":
            status = "FAILED"

        # Tính toán điểm số theo Dream-RSI Reward/Cost Function
        score = 0.0
        if flag_reached:
            score += scoring.get("flag_reward", 10000)

        score += executor_actions * scoring.get("cost_per_executor_action", -10)
        score += advisor_calls * scoring.get("cost_per_advisor_call", -30)
        score += dead_branches * scoring.get("penalty_dead_branch", -20)

        notes = (
            f"Policy {policy.name} ({policy.version}) replay: "
            f"{status} sau {steps} bước. "
            f"Advisor calls: {advisor_calls}, Actions: {executor_actions}, Pruned dead branches: {dead_branches}."
        )

        return ReplayResult(
            challenge_id=tree.challenge_id,
            policy_name=policy.name,
            policy_version=policy.version,
            success=flag_reached,
            flag_found=flag_reached,
            status=status,
            steps_taken=steps,
            advisor_calls=advisor_calls,
            executor_actions=executor_actions,
            dead_branches_pruned=dead_branches,
            score=score,
            path_taken=path_taken,
            notes=notes,
        )
