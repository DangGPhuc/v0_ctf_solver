import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from rich.console import Console

from ..models import ChallengeFingerprint
from ..knowledge.provider import KnowledgeProvider
from ..knowledge.models import KnowledgeQuery, RetrievedKnowledgeContext
from ..triage.fingerprint import FingerprintEngine
from ..prompts import (
    PromptCompiler,
    PromptSpec,
    StateCapsule,
)
from ..execution.policy import ExecutionCapabilities

console = Console()


class ContextBuilder:
    """
    Builds structured, auditable State Capsules and compiles advisor prompts.
    Coordinates:
      1. Challenge metadata & filesystem fingerprinting.
      2. Knowledge retrieval with explicit error taxonomy.
      3. State Capsule compression (facts, rejected hypotheses, recent experiments).
      4. PromptSpec compilation and lint validation.
    """

    def __init__(
        self,
        knowledge_provider: Optional[KnowledgeProvider] = None,
        policy: Optional[Any] = None,
    ):
        self.knowledge_provider = knowledge_provider
        self.policy = policy

    def compile(
        self,
        challenge_id: Any,
        chall_dir: Path,
        meta: Dict[str, Any],
        state: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Gom ngữ cảnh theo chuẩn State Capsule & Prompt Compiler:
        - Rút gọn tri thức xác minh, giả thuyết bác bỏ, thực nghiệm gần nhất thành State Capsule
        - Gắn kèm Context Artifacts (Metadata, Connection, Hints, Solver preview)
        - Biên dịch thành Template E (Auditable Reasoning) cho Strategic Advisor
        """
        name = meta.get("name", f"Challenge_{challenge_id}")
        category = meta.get("category", "Misc")
        points = meta.get("points", 0)
        desc = meta.get("description", "Không có mô tả.")
        conn = meta.get("connection_info", "")
        hints = meta.get("hints", [])

        hints_text = (
            "\n".join([f"- Hint: {h.get('content', str(h)) if isinstance(h, dict) else str(h)}" for h in hints])
            if hints
            else "*Không có hint.*"
        )

        # 1. Thu thập Knowledge Cards qua KnowledgeProvider
        retrieved_cards: List[RetrievedKnowledgeContext] = []
        retrieval_status: str = "SUCCESS"
        retrieval_error: Optional[str] = None

        active_hypo_stmt = None
        active_h_id = state.get("active_hypothesis_id") or state.get("active_hypothesis")
        hypotheses_list = state.get("hypotheses", [])
        if active_h_id and hypotheses_list:
            for h in hypotheses_list:
                h_id = h.get("id") if isinstance(h, dict) else getattr(h, "id", "")
                if h_id == active_h_id:
                    active_hypo_stmt = h.get("statement") if isinstance(h, dict) else getattr(h, "statement", "")
                    break
        if not active_hypo_stmt and isinstance(state.get("active_hypothesis"), str) and not state.get("active_hypothesis", "").startswith("H"):
            active_hypo_stmt = state.get("active_hypothesis")

        # Extract deep fingerprint
        fingerprint = FingerprintEngine.extract(
            meta=meta,
            chall_dir=chall_dir,
            active_hypothesis=active_hypo_stmt,
        )

        if self.knowledge_provider:
            try:
                kq = fingerprint.to_knowledge_query(hypothesis=active_hypo_stmt)
                hits = self.knowledge_provider.search(kq, limit=5)
                if not hits:
                    retrieval_status = "NO_MATCH"
                else:
                    for h in hits:
                        doc = self.knowledge_provider.fetch(h)
                        if doc:
                            retrieved_cards.append(RetrievedKnowledgeContext.from_doc(doc, confidence=h.score))
            except Exception as e:
                err_str = str(e).lower()
                if "offline" in err_str:
                    retrieval_status = "OFFLINE"
                elif any(k in err_str for k in ["401", "403", "auth", "credential", "unauthorized"]):
                    retrieval_status = "AUTH_FAILED"
                elif any(k in err_str for k in ["timeout", "connection", "network", "unavailable"]):
                    retrieval_status = "REMOTE_UNAVAILABLE"
                elif any(k in err_str for k in ["json", "parse", "decode"]):
                    retrieval_status = "PARSE_ERROR"
                else:
                    retrieval_status = "INTERNAL_ERROR"
                retrieval_error = str(e)
                console.print(f"[yellow]⚠️ Knowledge retrieval failed [{retrieval_status}]: {e}. Continuing with 0 retrieved cards.[/yellow]")
        else:
            retrieval_status = "NO_PROVIDER"

        # 2. Xây dựng State Capsule
        depth = 4
        if self.policy and hasattr(self.policy, "prompt_policy"):
            depth = self.policy.prompt_policy.get("recent_nodes_depth", 4)

        state_capsule = PromptCompiler.build_state_capsule(
            chall_dir=chall_dir,
            state=state,
            max_recent=depth,
            retrieved_cards=retrieved_cards,
        )

        # 3. Thu thập Focus Artifacts (Solver preview)
        max_lines = 40
        if self.policy and hasattr(self.policy, "executor"):
            max_lines = self.policy.executor.get("max_raw_log_lines", 40)

        solver_file = chall_dir / "work" / "solve.py"
        solver_snippet = None
        if solver_file.exists():
            content = solver_file.read_text(encoding="utf-8")
            solver_snippet = "\n".join(content.splitlines()[:max_lines])

        context_artifacts = {
            "challenge_metadata": (
                f"- Tên bài: {name} (ID: {challenge_id}) | Category: {category} | Points: {points}\n"
                f"- Connection: {conn or 'Chưa có'}\n\n"
                f"**Đề bài**:\n{desc}\n\n"
                f"**Gợi ý**:\n{hints_text}"
            ),
            "execution_capabilities": ExecutionCapabilities.detect().describe_for_advisor(),
        }
        if solver_snippet:
            context_artifacts["solver_preview"] = f"```python\n{solver_snippet}\n```"

        active_hypo = state.get("active_hypothesis")
        task_obj = (
            f"Phân tích chiến lược giải bài CTF {name} ({category}). "
            + (f"Kiểm chứng giả thuyết đang kích hoạt: {active_hypo}" if active_hypo and active_hypo != "Chưa xác định" else "Đề xuất các giả thuyết khai thác khả dĩ và kế hoạch hành động chi tiết.")
        )

        spec = PromptSpec(
            task_objective=task_obj,
            target_agent="advisor",
            state_capsule=state_capsule,
            allowed_scope=[
                f"Phân tích artifacts trong thư mục challenge '{chall_dir.name}'",
                "Sử dụng IDA Pro MCP / Ghidra để decompile logic",
                "Chạy debugger (GDB/GEF/Pwntools) trong container/môi trường",
                f"Kết nối tới challenge server ({conn or 'local binary'})",
            ],
            forbidden_scope=[
                "Không hallucinate flag format hoặc địa chỉ hàm không tồn tại",
                "Không chạy bruteforce ngẫu nhiên không có cơ sở lý thuyết",
                "Không lặp lại các giả thuyết đã bị bác bỏ (Rejected) trong State Capsule",
            ],
            stop_conditions=[
                "Giả thuyết được xác nhận (CONFIRMED) bởi leak bộ nhớ hoặc thực thi thành công",
                "Giả thuyết bị bác bỏ (REJECTED) do logic code hoàn toàn mâu thuẫn",
                "Sau 2 lần thực nghiệm liên tiếp không thu được thêm bằng chứng mới",
            ],
            evidence_contract=[
                "Giá trị thanh ghi, offset hàm hoặc câu lệnh C sau decompile chính xác",
                "Output từ debugger hoặc phản hồi mạng có thể tái lập",
                "Phân tích khác biệt (analysis_diff) giữa kỳ vọng và thực tế",
            ],
            success_criteria=[
                "Đề xuất tối đa 2 giả thuyết xếp hạng (H1, H2) kèm giả định rõ ràng",
                "Lệnh hoặc script cụ thể cho Executor thực hiện ngay lập tức",
                "Chỉ định rõ điều kiện dừng và các nhánh cần cắt tỉa (prune)",
            ],
            output_schema="Auditable Reasoning (Template E - 6 phần chuẩn)",
            target_backend="chatgpt",
            context_artifacts=context_artifacts,
        )

        full_prompt, violations = PromptCompiler.compile_advisor_prompt(
            spec,
            auto_repair=True,
        )

        advisor_dir = chall_dir / ".advisor"
        return {
            "challenge_id": str(challenge_id),
            "challenge_name": name,
            "category": category,
            "prompt": full_prompt,
            "full_prompt": full_prompt,
            "state": state,
            "advisor_dir": advisor_dir,
            "spec": spec,
            "state_capsule": state_capsule,
            "retrieval_status": retrieval_status,
            "retrieval_error": retrieval_error,
            "fingerprint": fingerprint.model_dump(),
            "retrieved_cards": retrieved_cards,
            "violations": violations,
            "violations_detected": len(violations),
        }
