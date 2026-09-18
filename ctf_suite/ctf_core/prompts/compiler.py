import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .linter import LintViolation, PromptLinter
from .spec import PromptSpec
from .state_capsule import StateCapsule
from .templates import CTFTemplates


class PromptCompiler:
    """
    Bộ biên dịch Prompt (Prompt Compiler - chuẩn Prompt Master):
    Chuyển đổi PromptSpec qua bộ lọc PromptLinter, áp dụng mẫu Template H/E tương ứng,
    và xuất ra Prompt hợp đồng có tính ràng buộc cao nhất.
    """

    @classmethod
    def compile(cls, spec: PromptSpec, auto_repair: bool = True) -> Tuple[str, List[LintViolation]]:
        """Biên dịch tổng quát cho một PromptSpec."""
        if auto_repair:
            spec, violations = PromptLinter.lint_and_repair(spec)
        else:
            violations = PromptLinter.lint(spec)

        if spec.target_agent == "advisor":
            prompt_text = CTFTemplates.render_advisor_contract(spec)
        else:
            prompt_text = CTFTemplates.render_executor_contract(spec)

        return prompt_text, violations

    @classmethod
    def compile_advisor_prompt(cls, spec: PromptSpec, auto_repair: bool = True) -> Tuple[str, List[LintViolation]]:
        spec.target_agent = "advisor"
        return cls.compile(spec, auto_repair=auto_repair)

    @classmethod
    def compile_executor_task(cls, spec: PromptSpec, auto_repair: bool = True) -> Tuple[str, List[LintViolation]]:
        spec.target_agent = "executor"
        return cls.compile(spec, auto_repair=auto_repair)

    @classmethod
    def build_state_capsule(
        cls,
        chall_dir: Path,
        state: Dict[str, Any],
        max_recent: int = 4,
        retrieved_cards: Optional[List[Dict[str, Any]]] = None,
    ) -> StateCapsule:
        """Trích xuất và nén thông tin từ workspace thành StateCapsule."""
        chall_id = state.get("challenge_id", chall_dir.name)
        chall_name = state.get("challenge_name", chall_dir.name)
        category = state.get("category", "Misc")
        advisor_dir = chall_dir / ".advisor"

        # 1. Trích xuất Confirmed Facts từ findings.md
        confirmed_facts = []
        findings_file = advisor_dir / "findings.md"
        if findings_file.is_file():
            content = findings_file.read_text(encoding="utf-8")
            for line in content.splitlines():
                line_str = line.strip()
                if line_str.startswith("- **") or line_str.startswith("- `"):
                    confirmed_facts.append(line_str.lstrip("- "))
        confirmed_facts = confirmed_facts[:8]  # Giữ tối đa 8 facts then chốt

        # 2. Trích xuất Rejected Hypotheses từ tree.json hoặc experiments.jsonl
        rejected_hypotheses = []
        tree_file = advisor_dir / "tree.json"
        if tree_file.is_file():
            try:
                tree_data = json.loads(tree_file.read_text(encoding="utf-8"))
                for nid, n in tree_data.get("nodes", {}).items():
                    if n.get("status") in ["rejected", "pruned"]:
                        rejected_hypotheses.append({
                            "name": n.get("name", nid),
                            "reason": n.get("payload", {}).get("diff") or n.get("payload", {}).get("observed") or "Rejected",
                        })
            except Exception:
                pass

        # 3. Trích xuất Recent Progress từ experiments.jsonl
        recent_progress = []
        exp_file = advisor_dir / "experiments.jsonl"
        if exp_file.is_file():
            try:
                lines = [l.strip() for l in exp_file.read_text(encoding="utf-8").splitlines() if l.strip()]
                for l in lines[-max_recent:]:
                    entry = json.loads(l)
                    recent_progress.append({
                        "id": entry.get("id", "EXP"),
                        "status": entry.get("status", "UNKNOWN"),
                        "actions": entry.get("actions", "")[:80],
                        "observed": entry.get("observed", "")[:80],
                    })
            except Exception:
                pass

        # 4. Trích xuất Retrieved Hints từ Thẻ Tri Thức tương tự
        retrieved_hints = []
        if retrieved_cards:
            for c in retrieved_cards:
                c_content = c.get("content", "")
                c_lines = c_content.splitlines()
                for cl in c_lines:
                    if cl.strip().startswith("- **") or cl.strip().startswith("1."):
                        retrieved_hints.append({
                            "source": c.get("name", "Card"),
                            "hint": cl.strip()[:100],
                        })
                        if len(retrieved_hints) >= 2:
                            break

        return StateCapsule(
            challenge_id=str(chall_id),
            challenge_name=chall_name,
            category=category,
            confirmed_facts=confirmed_facts,
            active_hypothesis=state.get("active_hypothesis"),
            rejected_hypotheses=rejected_hypotheses,
            recent_progress=recent_progress,
            unresolved_questions=[],
            retrieved_hints=retrieved_hints,
        )
