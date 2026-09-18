from typing import Any, Dict, List, Tuple
from rich.console import Console
from rich.table import Table

from .policy import ExplorationPolicy
from .simulator import ReplayResult, ReplaySimulator
from .tree import DiscoveryTree

console = Console()


class PolicyScorer:
    """
    Chấm điểm, so sánh và đánh giá hiệu năng giữa các ExplorationPolicy
    trên tập hợp các cây khám phá (Discovery Trees) lịch sử.
    """

    @classmethod
    def evaluate_policy(
        cls,
        policy: ExplorationPolicy,
        trees: List[DiscoveryTree],
    ) -> Dict[str, Any]:
        sim = ReplaySimulator(policy)
        results: List[ReplayResult] = []

        total_score = 0.0
        solved_count = 0
        total_steps = 0
        total_advisor_calls = 0
        total_actions = 0

        for tree in trees:
            res = sim.simulate(tree)
            results.append(res)
            total_score += res.score
            total_steps += res.steps_taken
            total_advisor_calls += res.advisor_calls
            total_actions += res.executor_actions
            if res.success:
                solved_count += 1

        n = len(trees) or 1
        return {
            "policy_name": policy.name,
            "policy_version": policy.version,
            "total_challenges": len(trees),
            "solved_count": solved_count,
            "solve_rate": (solved_count / n) * 100.0,
            "total_score": total_score,
            "avg_score": total_score / n,
            "avg_steps": total_steps / n,
            "avg_advisor_calls": total_advisor_calls / n,
            "avg_actions": total_actions / n,
            "individual_results": results,
        }

    @classmethod
    def compare_policies(
        cls,
        policy_a: ExplorationPolicy,
        policy_b: ExplorationPolicy,
        trees: List[DiscoveryTree],
    ) -> Table:
        """
        So sánh trực tiếp Policy A (Incumbent) vs Policy B (Candidate)
        trên cùng một tập dữ liệu lịch sử theo chuẩn Dream-RSI.
        """
        eval_a = cls.evaluate_policy(policy_a, trees)
        eval_b = cls.evaluate_policy(policy_b, trees)

        table = Table(title="📊 Policy Benchmark Comparison (Dream-RSI Offline Simulation)")
        table.add_column("Chỉ Số Đánh Giá", style="cyan bold")
        table.add_column(f"Policy A ({eval_a['policy_name']})", style="yellow")
        table.add_column(f"Policy B ({eval_b['policy_name']})", style="green")
        table.add_column("Khác Biệt (Delta)", style="bold")

        # Solve Rate
        rate_diff = eval_b["solve_rate"] - eval_a["solve_rate"]
        color = "green" if rate_diff >= 0 else "red"
        table.add_row(
            "Tỷ Lệ Giải Thành Công",
            f"{eval_a['solved_count']}/{eval_a['total_challenges']} ({eval_a['solve_rate']:.1f}%)",
            f"{eval_b['solved_count']}/{eval_b['total_challenges']} ({eval_b['solve_rate']:.1f}%)",
            f"[{color}]{rate_diff:+.1f}%[/]",
        )

        # Avg Steps
        steps_diff = eval_b["avg_steps"] - eval_a["avg_steps"]
        color = "green" if steps_diff <= 0 else "red"
        table.add_row(
            "Số Bước Trung Bình",
            f"{eval_a['avg_steps']:.1f}",
            f"{eval_b['avg_steps']:.1f}",
            f"[{color}]{steps_diff:+.1f} bước[/]",
        )

        # Advisor Calls
        calls_diff = eval_b["avg_advisor_calls"] - eval_a["avg_advisor_calls"]
        color = "green" if calls_diff <= 0 else "red"
        table.add_row(
            "Số Lần Gọi Cố Vấn TB",
            f"{eval_a['avg_advisor_calls']:.1f}",
            f"{eval_b['avg_advisor_calls']:.1f}",
            f"[{color}]{calls_diff:+.1f} lần[/]",
        )

        # Total Score
        score_diff = eval_b["total_score"] - eval_a["total_score"]
        color = "green" if score_diff >= 0 else "red"
        table.add_row(
            "Tổng Điểm Hiệu Năng",
            f"{eval_a['total_score']:.0f}",
            f"{eval_b['total_score']:.0f}",
            f"[{color}]{score_diff:+.0f}[/]",
        )

        return table
