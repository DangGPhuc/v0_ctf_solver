import datetime
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..models import Challenge, AdvisorGuidance, Hypothesis, Action, ExecutionResult, AdvisorResult
from ..runtime.manager import RuntimeManager
from ..advisor.browser_bridge import BrowserBridge
from ..triage.static import StaticTriage
from ..knowledge.provider import KnowledgeProvider
from ..knowledge.github_provider import GitHubKnowledgeProvider
from ..knowledge.models import KnowledgeQuery
from ..config import load_config
from ..meta.tree import DiscoveryTree, DiscoveryNode
from ..meta.event_recorder import EventRecorder
from ..meta.policy import ExplorationPolicy
from ..meta.simulator import ReplaySimulator, ReplayResult
from ..meta.knowledge_compiler import KnowledgeCompiler
from ..prompts import (
    PromptCompiler,
    PromptSpec,
    PromptLinter,
    LintViolation,
    CTFTemplates,
    StateCapsule,
)

console = Console()


class AdvisorService:
    """
    Subsystem quản lý chu trình tương tác hai chiều và siêu học (Meta-Layer):
    - Executor (Anti-IDE / OpenCode): Thực thi lệnh, chạy debugger, compile evidence
    - Strategic Advisor (ChatGPT Web qua Oracle): Tư duy phân tích, lập giả thuyết, định hướng
    - Actuator (BrowserSkill): Thao tác website/portal
    - Escalation (PAL MCP): Hội chẩn đa mô hình khi hết Hypothesis Budget
    - Meta-Layer (Dream-RSI): Ghi nhận DiscoveryTree (DAG), ExplorationPolicy, Offline Replay Simulator,
      và Declarative Technique Cards.
    """

    def __init__(
        self,
        workspace_dir: Optional[Path] = None,
        runtime_manager: Optional[RuntimeManager] = None,
        event_id: Optional[str] = None,
        knowledge_provider: Optional[KnowledgeProvider] = None,
        browser_bridge: Optional[BrowserBridge] = None,
    ):
        self.workspace_dir = Path(workspace_dir).resolve() if workspace_dir else Path.cwd()
        self.runtime_manager = runtime_manager or RuntimeManager()
        self.event_id = event_id or "default_event"
        self.policy = ExplorationPolicy.load_active_policy()
        self.kb_compiler = KnowledgeCompiler()
        self.browser_bridge = browser_bridge or BrowserBridge()

        cfg = load_config(self.workspace_dir)
        if knowledge_provider:
            self.knowledge_provider = knowledge_provider
        elif getattr(cfg, "knowledge_enabled", True):
            self.knowledge_provider = GitHubKnowledgeProvider(
                repo=cfg.knowledge_repo,
                ref=cfg.knowledge_ref,
                offline=cfg.knowledge_offline,
                ttl_seconds=cfg.knowledge_cache_ttl,
            )
        else:
            self.knowledge_provider = GitHubKnowledgeProvider(offline=True)

    def _find_chall_dir(self, challenge_id: Any) -> Path:
        cp = self.runtime_manager.challenge_path(self.event_id, challenge_id)
        if cp.exists():
            return cp
        raise ValueError(f"Runtime challenge directory not materialized for ID: {challenge_id}")

    def get_advisor_dir(self, challenge_id: Any) -> Path:
        chall_dir = self._find_chall_dir(challenge_id)
        advisor_dir = chall_dir / ".advisor"
        advisor_dir.mkdir(parents=True, exist_ok=True)
        return advisor_dir

    def init_challenge_advisor(self, challenge_id: Any, force: bool = False) -> Dict[str, Any]:
        """
        Khởi tạo cấu trúc .advisor/ cho challenge:
        - state.json: Lưu operational state, session Oracle, hypothesis budget
        - findings.md: Lưu các phát hiện đã xác nhận (L1 Context)
        - hypotheses.md: Lưu danh sách giả thuyết đang kiểm chứng
        - experiments.jsonl: Lịch sử thực nghiệm
        - guidance.md: Chỉ dẫn nhận từ ChatGPT Web
        - tree.json & events.jsonl: Cây Khám Phá DAG (chuẩn Dream-RSI)
        """
        chall_dir = self._find_chall_dir(challenge_id)
        advisor_dir = chall_dir / ".advisor"
        advisor_dir.mkdir(parents=True, exist_ok=True)

        meta = self.runtime_manager.read_challenge_state(self.event_id, challenge_id) or {}
        name = meta.get("name", f"Challenge_{challenge_id}")
        category = meta.get("category", "Misc")

        state_file = advisor_dir / "state.json"
        findings_file = advisor_dir / "findings.md"
        hypotheses_file = advisor_dir / "hypotheses.md"
        experiments_file = advisor_dir / "experiments.jsonl"
        guidance_file = advisor_dir / "guidance.md"
        tree_file = advisor_dir / "tree.json"

        # 1. Khởi tạo State Machine
        max_fails = self.policy.stopping.get("max_consecutive_failures", 2)
        if not state_file.exists() or force:
            initial_state = {
                "challenge_id": str(challenge_id),
                "challenge_name": name,
                "category": category,
                "status": "investigating",
                "phase": "triage",
                "iteration": 0,
                "oracle_session": None,
                "active_hypothesis": None,
                "active_hypothesis_node_id": None,
                "last_node_id": None,
                "hypothesis_budget": {
                    "max_failures_per_hypothesis": max_fails,
                    "current_failures": 0,
                    "total_consultations": 0,
                },
                "policy": {
                    "name": self.policy.name,
                    "version": self.policy.version,
                },
                "advisor_provider": "chatgpt-web",
                "escalated": False,
                "flag": None,
                "last_updated": datetime.datetime.now().isoformat(),
            }
            state_file.write_text(json.dumps(initial_state, indent=2, ensure_ascii=False), encoding="utf-8")

        # 2. Khởi tạo DiscoveryTree DAG & EventRecorder
        if not tree_file.exists() or force:
            tree = DiscoveryTree(challenge_id=str(challenge_id), challenge_name=name, category=category)
            recorder = EventRecorder(advisor_dir, tree=tree)
            init_node = recorder.record_event(
                event_type="init_challenge",
                actor="system",
                node_name=f"Init: {name}",
                payload={"category": category, "policy": self.policy.name},
                status="active",
            )
            # Cập nhật last_node_id vào state
            cur_state = json.loads(state_file.read_text(encoding="utf-8"))
            cur_state["last_node_id"] = init_node.node_id
            state_file.write_text(json.dumps(cur_state, indent=2, ensure_ascii=False), encoding="utf-8")

        # 3. Tự động scan static triage ban đầu để đưa vào findings.md
        if not findings_file.exists() or force:
            initial_findings = self._generate_initial_findings(chall_dir, meta)
            findings_file.write_text(initial_findings, encoding="utf-8")

        if not hypotheses_file.exists() or force:
            initial_hypo = (
                f"# Hypotheses Tracker: {name} (ID: {challenge_id})\n\n"
                "## 1. Active Hypotheses (Đang kiểm chứng)\n"
                "- **H1**: *(Chờ Strategic Advisor đề xuất sau vòng tham vấn đầu tiên)*\n\n"
                "## 2. Alternative Hypotheses (Dự phòng)\n"
                "- **H2**: *(Chờ Strategic Advisor đề xuất)*\n\n"
                "## 3. Discarded / Rejected Hypotheses (Đã bác bỏ)\n"
                "*(Chưa có)*\n"
            )
            hypotheses_file.write_text(initial_hypo, encoding="utf-8")

        if not experiments_file.exists():
            experiments_file.touch()

        if not guidance_file.exists() or force:
            initial_guidance = (
                f"# Strategic Guidance: {name}\n\n"
                "*Chưa có chỉ dẫn từ Strategic Advisor. Hãy chạy `./ctf advisor consult <ID>` để bắt đầu.*\n"
            )
            guidance_file.write_text(initial_guidance, encoding="utf-8")

        return {
            "challenge_id": str(challenge_id),
            "advisor_dir": advisor_dir,
            "state_file": state_file,
            "findings_file": findings_file,
            "hypotheses_file": hypotheses_file,
            "experiments_file": experiments_file,
            "tree_file": tree_file,
        }

    def _generate_initial_findings(self, chall_dir: Path, meta: Dict[str, Any]) -> str:
        """Thực hiện trích xuất tĩnh cơ bản để xây dựng L1 Context."""
        name = meta.get("name", "Chall")
        category = meta.get("category", "Misc")
        attachments_dir = (chall_dir / "input") if (chall_dir / "input").is_dir() else (chall_dir / "challenge")

        findings = [
            f"# Confirmed Findings & Evidence: {name} ({category})\n",
            "## 1. Protections & Binary Metadata (Checksec / File)",
        ]

        triage_lines = []
        if attachments_dir.is_dir():
            for fpath in attachments_dir.iterdir():
                if fpath.name in ["README.md", "metadata.json", "flag.txt"] or fpath.is_dir() or fpath.name.startswith("."):
                    continue
                if fpath.suffix in [".id0", ".id1", ".id2", ".nam", ".til", ".i64", ".idb"]:
                    continue

                # File command
                file_type = ""
                try:
                    res_file = subprocess.run(
                        ["file", "-b", str(fpath)], capture_output=True, text=True, timeout=5
                    )
                    file_type = res_file.stdout.strip()
                    triage_lines.append(f"- **{fpath.name}**: `{file_type}`")
                except Exception:
                    pass

                # Checksec nếu là ELF
                if "ELF" in file_type:
                    try:
                        res_cs = subprocess.run(
                            ["checksec", f"--file={fpath}"], capture_output=True, text=True, timeout=5
                        )
                        if res_cs.returncode == 0:
                            triage_lines.append(f"  ```text\n  {res_cs.stdout.strip()}\n  ```")
                    except Exception:
                        pass

                # Strings chắt lọc
                try:
                    res_str = subprocess.run(
                        ["strings", "-n", "7", str(fpath)], capture_output=True, text=True, timeout=5
                    )
                    lines = res_str.stdout.splitlines()
                    interesting = [
                        line
                        for line in lines
                        if re.search(
                            r"(flag|ctf|key|pass|admin|secret|system|bin/sh|eval|SELECT|INSERT|POST|GET)",
                            line,
                            re.IGNORECASE,
                        )
                    ][:15]
                    if interesting:
                        triage_lines.append("  - Interesting strings:")
                        for s in interesting:
                            triage_lines.append(f"    - `{s}`")
                except Exception:
                    pass

        if triage_lines:
            findings.extend(triage_lines)
        else:
            findings.append("- *Không tìm thấy tệp nhị phân hoặc thông tin tĩnh bổ sung.*")

        findings.append("\n## 2. Logic & Control Flow Observations (Reversing / Static Audit)")
        findings.append("- *Chưa phân tích hàm chính. Hãy bổ sung sau khi đọc mã/decompile.*")

        findings.append("\n## 3. Cryptographic / Network / Primitive Parameters")
        conn = meta.get("connection_info", "")
        if conn:
            findings.append(f"- Connection: `{conn}`")
        else:
            findings.append("- *Chưa có thông số kết nối hoặc tham số thuật toán.*")

        findings.append("\n## 4. Verified Constraints & Environmental Facts")
        findings.append("- Target runtime: Linux x86_64 (hoặc container theo đề)")

        return "\n".join(findings) + "\n"

    def _build_knowledge_query(
        self,
        meta: Dict[str, Any],
        chall_dir: Optional[Path] = None,
        active_hypothesis: Optional[str] = None,
    ) -> KnowledgeQuery:
        """
        Constructs a structured KnowledgeQuery using deep challenge fingerprint:
        - normalized category
        - challenge tags
        - detected file types & architecture
        - binary mitigations & protections (checksec)
        - domain-specific keywords extracted from description, hints, and hypothesis
        """
        from ctf_core.triage.fingerprint import FingerprintEngine
        hypo = active_hypothesis or meta.get("current_hypothesis")
        fingerprint = FingerprintEngine.extract(meta, chall_dir, hypo)
        return fingerprint.to_knowledge_query(hypothesis=hypo)

    def compile_context(self, challenge_id: Any) -> Dict[str, Any]:
        """
        Gom ngữ cảnh theo chuẩn State Capsule & Prompt Compiler (kết hợp Dream-RSI & Prompt Master):
        - Rút gọn tri thức xác minh, giả thuyết bác bỏ, thực nghiệm gần nhất thành State Capsule
        - Gắn kèm Context Artifacts (Metadata, Connection, Hints, Solver preview)
        - Chạy qua PromptLinter để loại bỏ 37 credit-killing anti-patterns
        - Biên dịch thành Template E (Auditable Reasoning) cho Strategic Advisor
        """
        chall_dir = self._find_chall_dir(challenge_id)
        advisor_dir = chall_dir / ".advisor"
        if not (advisor_dir / "state.json").exists():
            self.init_challenge_advisor(challenge_id)

        meta = self.runtime_manager.read_challenge_state(self.event_id, challenge_id) or {}
        state = json.loads((advisor_dir / "state.json").read_text(encoding="utf-8"))

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

        # 1. Thu thập Knowledge Cards tương tự qua KnowledgeProvider với Challenge Fingerprint đa chiều
        retrieved_cards = []
        try:
            active_hypo_stmt = None
            active_h_id = state.get("active_hypothesis")
            if active_h_id and hypotheses_list:
                for h in hypotheses_list:
                    if h.get("id") == active_h_id:
                        active_hypo_stmt = h.get("statement")
                        break

            kq = self._build_knowledge_query(
                meta=meta,
                chall_dir=chall_dir,
                active_hypothesis=active_hypo_stmt,
            )
            hits = self.knowledge_provider.search(kq, limit=5)
            for h in hits:
                doc = self.knowledge_provider.fetch(h)
                if doc:
                    retrieved_cards.append({
                        "id": doc.id,
                        "title": doc.title,
                        "category": doc.category,
                        "summary": doc.summary,
                        "technique": doc.technique_steps,
                    })
        except Exception as e:
            console.print(f"[yellow]⚠️ Knowledge query failed: {e}. Continuing with 0 retrieved cards.[/yellow]")

        # 2. Xây dựng State Capsule (chắt lọc tri thức xác thực, tránh tràn context)
        depth = self.policy.prompt_policy.get("recent_nodes_depth", 4)
        state_capsule = PromptCompiler.build_state_capsule(
            chall_dir=chall_dir,
            state=state,
            max_recent=depth,
            retrieved_cards=retrieved_cards,
        )

        # 3. Thu thập Focus Artifacts (Solver preview)
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

        return {
            "challenge_id": str(challenge_id),
            "challenge_name": name,
            "full_prompt": full_prompt,
            "state": state,
            "advisor_dir": advisor_dir,
            "spec": spec,
            "state_capsule": state_capsule,
            "violations": violations,
        }

    def _load_system_prompt(self) -> str:
        """Đọc file advisor_system_prompt.md từ thư mục skill hoặc template mặc định."""
        template_file = (
            self.workspace_dir
            / ".agents"
            / "skills"
            / "ctf-advisor"
            / "templates"
            / "advisor_system_prompt.md"
        )
        if template_file.exists():
            return template_file.read_text(encoding="utf-8")
        return (
            "Bạn là Strategic CTF Advisor cho Executor Agent (Anti-IDE/OpenCode).\n"
            "Hãy phân tích và trả về 6 phần chuẩn: ASSESSMENT, HYPOTHESES, NEXT_ACTIONS, "
            "EXPECTED_RESULTS, REQUESTED_EVIDENCE, STOP_CONDITION."
        )

    def consult(self, challenge_id: Any, extra_instruction: Optional[str] = None) -> Dict[str, Any]:
        """
        Thực hiện tham vấn Strategic Advisor (ChatGPT Web qua Oracle):
        - Nếu có Oracle: chạy `oracle --engine browser --browser-attach-running` (kèm `--followup` nếu đã có session).
        - Nếu không có Oracle hoặc lỗi: Fallback qua xclip và lưu file markdown.
        - Tự động ghi nhận nút vào DiscoveryTree (DAG).
        """
        ctx = self.compile_context(challenge_id)
        prompt = ctx["full_prompt"]
        if extra_instruction:
            prompt += f"\n\n### YÊU CẦU BỔ SUNG TỪ EXECUTOR:\n{extra_instruction}"

        advisor_dir = ctx["advisor_dir"]
        state = ctx["state"]
        oracle_session = state.get("oracle_session")

        # Lưu prompt vừa gửi
        prompt_file = advisor_dir / "latest_prompt.md"
        prompt_file.write_text(prompt, encoding="utf-8")

        oracle_cmd = self._build_oracle_command(prompt, oracle_session)
        advisor_response = None
        new_session = oracle_session
        provider = "chatgpt-web"

        if oracle_cmd:
            console.print("[cyan]🤖 Đang kết nối ChatGPT Web qua Oracle Browser Bridge...[/cyan]")
            try:
                res = subprocess.run(oracle_cmd, capture_output=True, text=True, timeout=120)
                if res.returncode == 0 and res.stdout.strip():
                    advisor_response = res.stdout.strip()
                    m = re.search(r"session[:\s]+([a-zA-Z0-9_\-]+)", advisor_response, re.IGNORECASE)
                    if m:
                        new_session = m.group(1)
                    console.print("[bold green]✔ Đã nhận phản hồi chiến lược từ ChatGPT Web qua Oracle![/bold green]")
                else:
                    console.print(f"[yellow]⚠️ Oracle trả về lỗi hoặc không có phản hồi: {res.stderr[:200]}[/yellow]")
            except Exception as e:
                console.print(f"[yellow]⚠️ Lỗi khi thực thi Oracle CLI: {e}[/yellow]")

        # Fallback Mechanism
        if not advisor_response:
            console.print("[yellow]🔄 Chuyển sang chế độ Fallback: Copy Prompt vào Clipboard & Mở Firefox...[/yellow]")
            self.browser_bridge.copy_to_clipboard(prompt)
            self.browser_bridge.open_firefox("https://chatgpt.com/")
            console.print("[green]✔ Đã copy Prompt vào Clipboard hệ thống! Bạn chỉ cần ấn Ctrl+V trên Firefox.[/green]")

            adv_result = AdvisorResult(
                status="WAITING_FOR_MANUAL_RESPONSE",
                guidance=None,
                provider="firefox-fallback",
                message="Prompt copied to clipboard. Awaiting manual response in .advisor/guidance.md",
            )
            return {
                "challenge_id": str(challenge_id),
                "iteration": state.get("iteration", 0),
                "oracle_session": oracle_session,
                "provider": "firefox-fallback",
                "guidance_file": advisor_dir / "guidance.md",
                "guidance": None,
                "active_hypothesis": None,
                "status": "WAITING_FOR_MANUAL_RESPONSE",
                "advisor_result": adv_result,
            }

        # Ghi nhận guidance
        guidance_file = advisor_dir / "guidance.md"
        guidance_file.write_text(advisor_response, encoding="utf-8")

        # Cập nhật EventRecorder & DiscoveryTree
        recorder = EventRecorder(advisor_dir)
        parent_node_id = state.get("last_node_id") or recorder.tree.root_id
        consult_node = recorder.record_event(
            event_type="advisor_consultation",
            actor="advisor",
            parent_id=parent_node_id,
            node_name=f"Consultation #{state.get('iteration', 0) + 1}",
            payload={"extra_instruction": extra_instruction or "", "response_preview": advisor_response[:150]},
            cost={"tokens": len(prompt) // 4},
            status="active",
        )
        state["last_node_id"] = consult_node.node_id

        # Phân tích có cấu trúc thành AdvisorGuidance
        guidance = self.parse_advisor_response(advisor_response)
        if guidance.hypotheses:
            state["active_hypothesis"] = guidance.hypotheses[0].statement
            hypo_node = recorder.record_event(
                event_type="hypothesis",
                actor="advisor",
                parent_id=consult_node.node_id,
                node_name=f"{guidance.hypotheses[0].id}: {state['active_hypothesis'][:35]}",
                payload={"hypothesis": state["active_hypothesis"]},
                status="active",
            )
            state["active_hypothesis_node_id"] = hypo_node.node_id

        # Cập nhật state.json
        state["iteration"] = state.get("iteration", 0) + 1
        state["hypothesis_budget"]["total_consultations"] = state["hypothesis_budget"].get("total_consultations", 0) + 1
        state["oracle_session"] = new_session
        state["advisor_provider"] = provider
        state["last_updated"] = datetime.datetime.now().isoformat()

        (advisor_dir / "state.json").write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")

        adv_result = AdvisorResult(
            status="READY",
            guidance=guidance,
            provider=provider,
            message="Guidance received from strategic advisor",
        )

        return {
            "challenge_id": str(challenge_id),
            "iteration": state["iteration"],
            "oracle_session": new_session,
            "provider": provider,
            "guidance_file": guidance_file,
            "guidance": guidance,
            "active_hypothesis": state.get("active_hypothesis"),
            "status": "READY",
            "advisor_result": adv_result,
        }

    def import_manual_response(self, challenge_id: Any, response_content: Any) -> AdvisorResult:
        chall_dir = self._find_chall_dir(challenge_id)
        advisor_dir = chall_dir / ".advisor"
        advisor_dir.mkdir(parents=True, exist_ok=True)

        if isinstance(response_content, Path):
            response_text = response_content.read_text(encoding="utf-8")
        elif isinstance(response_content, str) and os.path.exists(response_content):
            response_text = Path(response_content).read_text(encoding="utf-8")
        else:
            response_text = str(response_content)

        guidance_file = advisor_dir / "guidance.md"
        guidance_file.write_text(response_text, encoding="utf-8")

        guidance = self.parse_advisor_response(response_text)
        state_file = advisor_dir / "state.json"
        state = json.loads(state_file.read_text(encoding="utf-8")) if state_file.is_file() else {}
        if guidance.hypotheses:
            state["active_hypothesis"] = guidance.hypotheses[0].statement
            state["iteration"] = state.get("iteration", 0) + 1
            state_file.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")

        return AdvisorResult(
            status="READY",
            guidance=guidance,
            provider="manual-import",
            message="Manual guidance imported and parsed successfully",
        )

    @staticmethod
    def parse_advisor_response(text: str) -> AdvisorGuidance:
        """Parse advisor markdown/text output into structured AdvisorGuidance."""
        if not text:
            return AdvisorGuidance(raw_text="")
        
        # 1. Try to extract JSON codeblock
        json_match = re.search(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", text)
        if json_match:
            try:
                data = json.loads(json_match.group(1))
                if isinstance(data, dict):
                    data["raw_text"] = text
                    return AdvisorGuidance.model_validate(data)
            except Exception:
                pass

        # 2. Heuristic parsing
        assessment = ""
        ass_m = re.search(r"(?i)(?:assessment|root cause|phân tích)[:\s]+([^\n]+)", text)
        if ass_m:
            assessment = ass_m.group(1).strip()
        else:
            first_lines = [l.strip() for l in text.splitlines() if l.strip() and not l.startswith("#")]
            assessment = first_lines[0] if first_lines else "Initial assessment"

        hypotheses: List[Hypothesis] = []
        hypo_matches = re.findall(r"(?i)(?:H\d+|Hypothesis\s*\d+)[:\s]+([^\n]+)", text)
        for idx, h_text in enumerate(hypo_matches, 1):
            hypotheses.append(Hypothesis(id=f"H{idx}", statement=h_text.strip()))
        if not hypotheses:
            hypotheses.append(Hypothesis(id="H1", statement="Inspect binary and test exploit payload"))

        next_actions: List[Action] = []
        actions_matches = re.findall(r"(?i)(?:Action\s*\d*|Step\s*\d*|\d+\.)[:\s]+([^\n]+)", text)
        for act_text in actions_matches:
            act_s = act_text.strip()
            if len(act_s) > 5 and not any(kw in act_s.lower() for kw in ["hypothesis", "assessment"]):
                next_actions.append(Action(type="command", command_or_task=act_s))
        if not next_actions:
            next_actions.append(Action(type="command", command_or_task="python3 solve.py"))

        requested_evidence: List[str] = []
        ev_m = re.findall(r"(?i)(?:evidence|proof)[:\s]+([^\n]+)", text)
        for ev in ev_m:
            requested_evidence.append(ev.strip())

        stop_conditions: List[str] = []
        stop_m = re.findall(r"(?i)(?:stop condition|dừng khi)[:\s]+([^\n]+)", text)
        for sc in stop_m:
            stop_conditions.append(sc.strip())

        return AdvisorGuidance(
            assessment=assessment,
            hypotheses=hypotheses,
            next_actions=next_actions,
            requested_evidence=requested_evidence,
            stop_conditions=stop_conditions,
            raw_text=text,
        )

    def _build_oracle_command(self, prompt: str, oracle_session: Optional[str] = None) -> Optional[List[str]]:
        oracle_bin = shutil.which("oracle")
        if oracle_bin:
            cmd = [oracle_bin, "--engine", "browser", "--browser-attach-running"]
            if oracle_session:
                cmd.extend(["--followup", oracle_session])
            cmd.extend(["-p", prompt])
            return cmd

        npx_bin = shutil.which("npx")
        if npx_bin:
            cmd = [npx_bin, "-y", "@steipete/oracle", "--engine", "browser", "--browser-attach-running"]
            if oracle_session:
                cmd.extend(["--followup", oracle_session])
            cmd.extend(["-p", prompt])
            return cmd

        return None

    def _copy_to_clipboard(self, text: str) -> bool:
        try:
            p = subprocess.Popen(["xclip", "-selection", "clipboard"], stdin=subprocess.PIPE)
            p.communicate(input=text.encode("utf-8"))
            return p.returncode == 0
        except Exception:
            return False

    def report_execution(
        self,
        challenge_id: Any,
        experiment_id_or_result: Any,
        actions: Optional[str] = None,
        observed: Optional[str] = None,
        status: Optional[str] = None,
        diff: Optional[str] = None,
        evidence: Optional[str] = None,
        open_questions: Optional[str] = None,
        auto_consult: bool = False,
    ) -> Dict[str, Any]:
        """
        Đóng gói báo cáo thực nghiệm của Executor, kiểm tra Hypothesis Budget,
        đồng bộ vào DiscoveryTree (DAG), và tự động gửi --followup vào Oracle.
        """
        if isinstance(experiment_id_or_result, ExecutionResult):
            experiment_id = experiment_id_or_result.experiment_id
            actions = actions or ("\n".join(experiment_id_or_result.actions) if experiment_id_or_result.actions else "Ran solver")
            observed = observed or experiment_id_or_result.observed
            status = status or experiment_id_or_result.status
            evidence = evidence or ("\n".join(experiment_id_or_result.evidence) if experiment_id_or_result.evidence else "")
            diff = diff or (experiment_id_or_result.stderr_tail if experiment_id_or_result.status in ["REJECTED", "ERROR"] else None)
        else:
            experiment_id = str(experiment_id_or_result)
            actions = actions or ""
            observed = observed or ""
            status = status or "INCONCLUSIVE"
        chall_dir = self._find_chall_dir(challenge_id)
        advisor_dir = chall_dir / ".advisor"
        state_file = advisor_dir / "state.json"
        if not state_file.exists():
            self.init_challenge_advisor(challenge_id)

        state = json.loads(state_file.read_text(encoding="utf-8"))
        status_clean = status.upper().strip()

        # 1. Ghi nhận vào experiments.jsonl
        exp_entry = {
            "id": experiment_id,
            "timestamp": datetime.datetime.now().isoformat(),
            "hypothesis": state.get("active_hypothesis"),
            "actions": actions,
            "observed": observed,
            "status": status_clean,
            "diff": diff or "",
            "evidence": evidence or "",
            "open_questions": open_questions or "",
        }
        with open(advisor_dir / "experiments.jsonl", "a", encoding="utf-8") as ef:
            ef.write(json.dumps(exp_entry, ensure_ascii=False) + "\n")

        # 2. Cập nhật DiscoveryTree (DAG)
        recorder = EventRecorder(advisor_dir)
        parent_node_id = state.get("active_hypothesis_node_id") or state.get("last_node_id") or recorder.tree.root_id

        # Tạo nút Action
        act_node = recorder.record_event(
            event_type="action",
            actor="executor",
            parent_id=parent_node_id,
            node_name=f"Action {experiment_id}",
            payload={"actions": actions, "experiment_id": experiment_id},
            cost={"tool_calls": 1},
            status="active",
        )

        # Tạo nút Observation nối tiếp nút Action
        obs_node = recorder.record_event(
            event_type="observation",
            actor="executor",
            parent_id=act_node.node_id,
            node_name=f"Obs {experiment_id}",
            payload={"observed": observed, "diff": diff or "", "evidence": evidence or ""},
            status=status_clean.lower(),
        )
        state["last_node_id"] = obs_node.node_id

        # 3. Quản lý Hypothesis Budget & Cắt Tỉa Nhánh Chết (Pruning)
        budget = state.setdefault("hypothesis_budget", {
            "max_failures_per_hypothesis": self.policy.stopping.get("max_consecutive_failures", 2),
            "current_failures": 0,
            "total_consultations": 0,
        })

        if status_clean == "REJECTED":
            budget["current_failures"] += 1
            # Cắt tỉa nhánh nếu chính sách yêu cầu
            if self.policy.branching.get("prune_dead_ends", True):
                recorder.tree.prune_subtree(act_node.node_id, reason=diff or observed)
                recorder.tree.save(recorder.tree_file)
                # Rollback last_node_id về cha của nhánh bị cắt tỉa
                state["last_node_id"] = parent_node_id

            if budget["current_failures"] >= budget.get("max_failures_per_hypothesis", 2):
                state["status"] = "stalled"
                console.print(
                    f"[bold red]🚨 HYPOTHESIS BUDGET EXCEEDED! Đã thất bại {budget['current_failures']} lần liên tiếp.[/bold red]\n"
                    f"[yellow]Khuyến nghị: Chạy `./ctf advisor escalate {challenge_id}` để kích hoạt thẩm định chéo PAL MCP![/yellow]"
                )
        elif status_clean == "CONFIRMED":
            budget["current_failures"] = 0
            state["status"] = "testing_hypothesis"
            act_node.status = "confirmed"
            obs_node.status = "confirmed"
            recorder.tree.save(recorder.tree_file)

        # 4. Tạo Execution Report theo template
        report_text = self._format_execution_report(
            chall_name=state.get("challenge_name", "Chall"),
            chall_id=str(challenge_id),
            category=state.get("category", "Misc"),
            iteration=state.get("iteration", 1),
            exp_id=experiment_id,
            active_hypo=state.get("active_hypothesis") or "Không có",
            actions=actions,
            observed=observed,
            status=status_clean,
            diff=diff,
            evidence=evidence,
            open_questions=open_questions,
        )

        report_file = advisor_dir / "latest_report.md"
        report_file.write_text(report_text, encoding="utf-8")

        state["last_updated"] = datetime.datetime.now().isoformat()
        state_file.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")

        # 5. Tự động gửi follow-up cho Oracle nếu được yêu cầu
        consult_res = None
        if auto_consult and state.get("status") != "stalled":
            console.print("[cyan]🔄 Đang tự động gửi báo cáo thực nghiệm lên Strategic Advisor qua Oracle followup...[/cyan]")
            consult_res = self.consult(challenge_id, extra_instruction=report_text)

        return {
            "challenge_id": str(challenge_id),
            "experiment_id": experiment_id,
            "status": status_clean,
            "budget": budget,
            "is_stalled": state.get("status") == "stalled",
            "report_file": report_file,
            "consult_res": consult_res,
        }

    def _format_execution_report(
        self,
        chall_name: str,
        chall_id: str,
        category: str,
        iteration: int,
        exp_id: str,
        active_hypo: str,
        actions: str,
        observed: str,
        status: str,
        diff: Optional[str],
        evidence: Optional[str],
        open_questions: Optional[str],
    ) -> str:
        clean_actions = actions.replace('"', '\\"').replace("\n", " ")
        clean_observed = observed.replace('"', '\\"').replace("\n", " ")
        clean_diff = (diff or "None").replace('"', '\\"').replace("\n", " ")
        return (
            f"# EXECUTOR EXECUTION REPORT (Template H Return Contract)\n\n"
            f"**Challenge**: {chall_name} (ID: {chall_id}) | **Category**: {category} | **Iteration**: #{iteration}\n"
            f"**Experiment ID**: {exp_id} | **Active Hypothesis**: {active_hypo}\n\n"
            f"```yaml\n"
            f"status: {status}\n"
            f"actions_executed: \"{clean_actions}\"\n"
            f"observed_evidence: \"{clean_observed}\"\n"
            f"analysis_diff: \"{clean_diff}\"\n"
            f"open_questions: \"{(open_questions or 'None').replace(chr(10), ' ')}\"\n"
            f"```\n\n"
            f"### EVIDENCE DETAILS (Bằng chứng trích lọc):\n"
            f"```text\n{evidence or 'None'}\n```\n\n"
            f"### NEXT CONSULTATION QUERY:\n"
            f"{open_questions or 'Advisor vui lòng thẩm định bằng chứng trên và chỉ dẫn bước tiếp theo.'}\n"
        )

    def escalate_pal(self, challenge_id: Any, reason: str) -> Dict[str, Any]:
        """
        Kích hoạt tầng thẩm định chéo PAL MCP khi ChatGPT Web bị sa lầy (tunnel vision):
        - Tạo prompt chất vấn giả định (Challenge Assumptions)
        - Đóng gói phản biện gửi lại cho Strategic Advisor
        - Ghi nút escalation vào DiscoveryTree
        """
        chall_dir = self._find_chall_dir(challenge_id)
        advisor_dir = chall_dir / ".advisor"
        state_file = advisor_dir / "state.json"
        state = json.loads(state_file.read_text(encoding="utf-8")) if state_file.exists() else {}

        name = state.get("challenge_name", f"Chall_{challenge_id}")
        active_hypo = state.get("active_hypothesis", "Chưa rõ")

        escalation_prompt = (
            f"### PAL ESCALATION REVIEW: CHALLENGE ASSUMPTIONS\n"
            f"Hội đồng thẩm định độc lập (PAL Consensus) được kích hoạt cho bài: {name}\n"
            f"- **Giả thuyết hiện tại bị bế tắc**: {active_hypo}\n"
            f"- **Lý do bế tắc**: {reason}\n\n"
            f"Yêu cầu: Hãy phản biện nghiêm ngặt giả định trên. Chỉ ra các góc khuất kỹ thuật "
            f"và đề xuất ít nhất 2 vector tấn công hoàn toàn khác (Alternative Vectors)."
        )

        escalation_file = advisor_dir / "escalation_review.md"
        escalation_file.write_text(escalation_prompt, encoding="utf-8")

        # Cập nhật tree.json
        recorder = EventRecorder(advisor_dir)
        esc_node = recorder.record_event(
            event_type="escalation",
            actor="evaluator",
            parent_id=state.get("last_node_id") or recorder.tree.root_id,
            node_name="PAL Escalation Review",
            payload={"reason": reason, "active_hypothesis": active_hypo},
            status="active",
        )

        state["escalated"] = True
        state["status"] = "investigating"
        state["last_node_id"] = esc_node.node_id
        state["hypothesis_budget"]["current_failures"] = 0
        state["last_updated"] = datetime.datetime.now().isoformat()
        state_file.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")

        console.print(f"[bold green]✔ Đã khởi tạo hồ sơ thẩm định chéo PAL tại: {escalation_file.name}[/bold green]")
        console.print("[cyan]Đang gửi hồ sơ phản biện vào phiên làm việc của Strategic Advisor...[/cyan]")

        return self.consult(challenge_id, extra_instruction=escalation_prompt)

    def mark_solved(self, challenge_id: Any, flag: str) -> Dict[str, Any]:
        """
        Đánh dấu bài đã giải thành công, thêm nút TERMINAL_FLAG vào DiscoveryTree,
        và tự động kích hoạt KnowledgeCompiler để tổng hợp Thẻ Tri Thức!
        """
        chall_dir = self._find_chall_dir(challenge_id)
        advisor_dir = chall_dir / ".advisor"
        state_file = advisor_dir / "state.json"
        state = json.loads(state_file.read_text(encoding="utf-8")) if state_file.exists() else {}

        recorder = EventRecorder(advisor_dir)
        flag_node = recorder.record_event(
            event_type="terminal_flag",
            actor="evaluator",
            parent_id=state.get("last_node_id") or recorder.tree.root_id,
            node_name="Flag Solved!",
            payload={"flag": flag},
            status="solved",
        )

        state["status"] = "solved"
        state["phase"] = "completed"
        state["flag"] = flag
        state["last_node_id"] = flag_node.node_id
        state["last_updated"] = datetime.datetime.now().isoformat()
        state_file.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")

        # Tự động trích xuất Thẻ Tri Thức (Declarative Memory)
        card_path = self.compile_knowledge(challenge_id, flag=flag)
        return {"challenge_id": str(challenge_id), "status": "solved", "flag": flag, "card_path": card_path}

    def compile_knowledge(self, challenge_id: Any, flag: Optional[str] = None) -> Path:
        """Trích xuất Thẻ Tri Thức từ DiscoveryTree của bài tập đã giải."""
        chall_dir = self._find_chall_dir(challenge_id)
        advisor_dir = chall_dir / ".advisor"
        recorder = EventRecorder(advisor_dir)

        solver_code = None
        solver_path = chall_dir / "work" / "solve.py"
        if solver_path.is_file():
            solver_code = solver_path.read_text(encoding="utf-8")

        findings_text = None
        findings_path = advisor_dir / "findings.md"
        if findings_path.is_file():
            findings_text = findings_path.read_text(encoding="utf-8")

        state_file = advisor_dir / "state.json"
        final_flag = flag
        if not final_flag and state_file.is_file():
            st = json.loads(state_file.read_text(encoding="utf-8"))
            final_flag = st.get("flag")

        card_path = self.kb_compiler.compile_challenge(
            tree=recorder.tree,
            flag=final_flag,
            solver_code=solver_code,
            findings_text=findings_text,
        )
        return card_path

    def get_discovery_tree(self, challenge_id: Any) -> DiscoveryTree:
        """Nạp DiscoveryTree của challenge."""
        chall_dir = self._find_chall_dir(challenge_id)
        tree_file = chall_dir / ".advisor" / "tree.json"
        if not tree_file.is_file():
            self.init_challenge_advisor(challenge_id)
        return DiscoveryTree.load(tree_file)

    def replay_simulation(
        self,
        challenge_id: Any,
        policy_file: Optional[Path] = None,
    ) -> ReplayResult:
        """Chạy mô phỏng Replay offline một ExplorationPolicy trên DiscoveryTree của bài tập."""
        tree = self.get_discovery_tree(challenge_id)
        policy = (
            ExplorationPolicy.load_from_file(policy_file)
            if policy_file
            else self.policy
        )
        sim = ReplaySimulator(policy=policy)
        return sim.simulate(tree)

    def get_status(self, challenge_id: Any) -> Dict[str, Any]:
        """Đọc và hiển thị bảng dashboard trạng thái ReAct của challenge."""
        chall_dir = self._find_chall_dir(challenge_id)
        advisor_dir = chall_dir / ".advisor"
        state_file = advisor_dir / "state.json"

        if not state_file.exists():
            return {"exists": False, "challenge_id": str(challenge_id)}

        state = json.loads(state_file.read_text(encoding="utf-8"))
        exps_file = advisor_dir / "experiments.jsonl"
        exps_count = 0
        if exps_file.exists():
            exps_count = len([line for line in exps_file.read_text(encoding="utf-8").splitlines() if line.strip()])

        tree_nodes_count = 0
        tree_file = advisor_dir / "tree.json"
        if tree_file.is_file():
            try:
                t = DiscoveryTree.load(tree_file)
                tree_nodes_count = len(t.nodes)
            except Exception:
                pass

        table = Table(title=f"🎯 ReAct Operational Dashboard: {state.get('challenge_name')} (ID: {challenge_id})")
        table.add_column("Chỉ Số", style="cyan bold")
        table.add_column("Giá Trị Hiện Tại", style="white")

        table.add_row("Status", f"[{'green' if state.get('status') == 'solved' else 'yellow'}]{state.get('status')}[/]")
        table.add_row("Phase", state.get("phase", "triage"))
        table.add_row("Iteration", str(state.get("iteration", 0)))
        table.add_row("Active Hypothesis", state.get("active_hypothesis") or "[dim]None[/dim]")
        budget = state.get("hypothesis_budget", {})
        table.add_row(
            "Budget Fails",
            f"{budget.get('current_failures', 0)} / {budget.get('max_failures_per_hypothesis', 2)}",
        )
        table.add_row("Active Policy", f"{self.policy.name} (v{self.policy.version})")
        table.add_row("Total Consultations", str(budget.get("total_consultations", 0)))
        table.add_row("Total Experiments", str(exps_count))
        table.add_row("DAG Tree Nodes", f"{tree_nodes_count} nút")
        table.add_row("Oracle Session", state.get("oracle_session") or "[dim]None[/dim]")
        table.add_row("Advisor Provider", state.get("advisor_provider", "unknown"))
        table.add_row("Escalated via PAL", "✔ Có" if state.get("escalated") else "✖ Chưa")

        console.print(table)
        return {"exists": True, "state": state, "total_experiments": exps_count, "tree_nodes": tree_nodes_count}

    def get_state_capsule(self, challenge_id: Any) -> StateCapsule:
        """Trích xuất State Capsule cô đọng của challenge."""
        ctx = self.compile_context(challenge_id)
        return ctx["state_capsule"]

    def lint_challenge_prompt(
        self, challenge_id: Any, target_agent: str = "advisor"
    ) -> Tuple[PromptSpec, List[LintViolation]]:
        """Kiểm tra PromptSpec của challenge bằng PromptLinter."""
        ctx = self.compile_context(challenge_id)
        spec: PromptSpec = ctx["spec"]
        spec.target_agent = target_agent
        if target_agent == "executor":
            spec.task_objective = f"Thực hiện kiểm chứng giả thuyết: {spec.state_capsule.active_hypothesis or 'Triage ban đầu'}"
        repaired_spec, violations = PromptLinter.lint_and_repair(spec)
        return repaired_spec, violations

    def show_compiled_prompt(
        self, challenge_id: Any, target_agent: str = "advisor"
    ) -> Tuple[str, List[LintViolation]]:
        """Biên dịch và hiển thị Prompt hợp đồng (Template H/E) cho challenge."""
        ctx = self.compile_context(challenge_id)
        spec: PromptSpec = ctx["spec"]
        spec.target_agent = target_agent
        if target_agent == "executor":
            spec.task_objective = f"Thực nghiệm kiểm chứng giả thuyết: {spec.state_capsule.active_hypothesis or 'Triage ban đầu'}"
        return PromptCompiler.compile(spec, auto_repair=True)

