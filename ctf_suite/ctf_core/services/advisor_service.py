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
from ..advisor import (
    ContextBuilder,
    GuidanceParser,
    BaseAdvisorProvider,
    OracleAdvisorProvider,
    ManualAdvisorProvider,
)
from ..triage.static import StaticTriage
from ..knowledge.provider import KnowledgeProvider
from ..knowledge.github_provider import GitHubKnowledgeProvider
from ..knowledge.models import KnowledgeQuery, RetrievedKnowledgeContext
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
from ..experiments import (
    HypothesisManager,
    ExperimentLedger,
    EvidenceEvaluator,
    ExperimentEvaluation,
    Experiment,
    ExperimentProposal,
    UnknownExperimentError,
    UnknownHypothesisError,
)

console = Console()


class AdvisorService:
    """
    Subsystem quản lý chu trình tương tác hai chiều và siêu học (Meta-Layer):
    - Executor (Anti-IDE / OpenCode): Thực thi lệnh, chạy debugger, compile evidence
    - Strategic Advisor (ChatGPT Web qua Oracle): Tư duy phân tích, lập giả thuyết, định hướng
    - Actuator (BrowserSkill): Thao tác website/portal
    - Strategic Escalation: Phá vỡ bế tắc giả định (Strategic Assumption Challenge & Reframe) khi hết Hypothesis Budget
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

        self.context_builder = ContextBuilder(knowledge_provider=self.knowledge_provider, policy=self.policy)
        self.guidance_parser = GuidanceParser
        self.advisor_provider = OracleAdvisorProvider()

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
        """Thực hiện trích xuất tĩnh an toàn thuần Python để xây dựng L1 Context."""
        name = meta.get("name", "Chall")
        category = meta.get("category", "Misc")
        attachments_dir = (chall_dir / "input") if (chall_dir / "input").is_dir() else (chall_dir / "challenge")

        findings = [
            f"# Confirmed Findings & Evidence: {name} ({category})\n",
            "## 1. Protections & Binary Metadata (Checksec / File)",
        ]

        triage_reports: List[str] = []
        if attachments_dir.is_dir():
            triage_reports = StaticTriage.triage_directory(attachments_dir)

        if triage_reports:
            findings.extend(triage_reports)
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
        return self.context_builder.compile(
            challenge_id=challenge_id,
            chall_dir=chall_dir,
            meta=meta,
            state=state,
        )


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

        # Delegate consultation to advisor provider
        adv_res = self.advisor_provider.consult(
            prompt=prompt,
            oracle_session=oracle_session,
            challenge_id=str(challenge_id),
        )

        advisor_response = adv_res.raw_response
        new_session = adv_res.session_id or oracle_session
        provider = adv_res.provider

        # Fallback Mechanism
        if adv_res.status == "PROVIDER_UNAVAILABLE" or not advisor_response:
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
        hypo_mgr = HypothesisManager.load(advisor_dir / "hypotheses.json")
        if guidance.hypotheses:
            hypo_mgr.register(guidance.hypotheses)
            active_h = hypo_mgr.get_active()
            if active_h:
                state["active_hypothesis"] = active_h.statement
                state["active_hypothesis_id"] = active_h.id
            hypo_node = recorder.record_event(
                event_type="hypothesis",
                actor="advisor",
                parent_id=consult_node.node_id,
                node_name=f"{guidance.hypotheses[0].id}: {state['active_hypothesis'][:35]}",
                payload={"hypothesis": state["active_hypothesis"]},
                status="active",
            )
            state["active_hypothesis_node_id"] = hypo_node.node_id
        hypo_mgr.save(advisor_dir / "hypotheses.json")

        # Ghi nhận experiment được đề xuất vào ExperimentLedger trước khi thực thi
        ledger = ExperimentLedger(advisor_dir)
        canonical_exp_id = None
        if guidance.experiment and guidance.experiment.execution_plan:
            canonical_exp = ledger.create(
                hypothesis_id=guidance.experiment.hypothesis_id,
                intent=guidance.experiment.intent,
                actions=guidance.experiment.execution_plan,
                expected_evidence=guidance.experiment.expected_evidence,
                contradicting_evidence=guidance.experiment.contradicting_evidence,
            )
            canonical_exp_id = canonical_exp.experiment_id
            state["active_experiment_id"] = canonical_exp_id
        elif guidance.execution_plan:
            hypo_id = guidance.hypotheses[0].id if guidance.hypotheses else (state.get("active_hypothesis_id") or "H1")
            canonical_exp = ledger.create(
                hypothesis_id=hypo_id,
                intent=guidance.assessment or "Execute solver plan",
                actions=guidance.execution_plan,
                expected_evidence=guidance.requested_evidence,
            )
            canonical_exp_id = canonical_exp.experiment_id
            state["active_experiment_id"] = canonical_exp_id

        # Cập nhật state.json
        state["iteration"] = state.get("iteration", 0) + 1
        state["hypothesis_budget"]["total_consultations"] = state["hypothesis_budget"].get("total_consultations", 0) + 1
        state["oracle_session"] = new_session
        state["advisor_provider"] = provider
        state["last_updated"] = datetime.datetime.now().isoformat()

        (advisor_dir / "state.json").write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")

        if guidance.validation_error:
            adv_status = "ERROR"
            adv_msg = f"Advisor structured JSON payload invalid: {guidance.validation_error}"
        else:
            adv_status = "READY"
            adv_msg = "Guidance received from strategic advisor"

        adv_result = AdvisorResult(
            status=adv_status,
            guidance=guidance,
            provider=provider,
            message=adv_msg,
        )

        return {
            "challenge_id": str(challenge_id),
            "iteration": state["iteration"],
            "oracle_session": new_session,
            "provider": provider,
            "guidance_file": guidance_file,
            "guidance": guidance,
            "active_hypothesis": state.get("active_hypothesis"),
            "active_experiment_id": canonical_exp_id,
            "status": adv_status,
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
        hypo_mgr = HypothesisManager.load(advisor_dir / "hypotheses.json")
        if guidance.hypotheses:
            hypo_mgr.register(guidance.hypotheses)
            active_h = hypo_mgr.get_active()
            if active_h:
                state["active_hypothesis"] = active_h.statement
                state["active_hypothesis_id"] = active_h.id
            state["iteration"] = state.get("iteration", 0) + 1
            state_file.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
        hypo_mgr.save(advisor_dir / "hypotheses.json")

        ledger = ExperimentLedger(advisor_dir)
        canonical_exp_id = None
        if guidance.experiment and guidance.experiment.execution_plan:
            canonical_exp = ledger.create(
                hypothesis_id=guidance.experiment.hypothesis_id,
                intent=guidance.experiment.intent,
                actions=guidance.experiment.execution_plan,
                expected_evidence=guidance.experiment.expected_evidence,
                contradicting_evidence=guidance.experiment.contradicting_evidence,
            )
            canonical_exp_id = canonical_exp.experiment_id
            state["active_experiment_id"] = canonical_exp_id
        elif guidance.execution_plan:
            hypo_id = guidance.hypotheses[0].id if guidance.hypotheses else (state.get("active_hypothesis_id") or "H1")
            canonical_exp = ledger.create(
                hypothesis_id=hypo_id,
                intent=guidance.assessment or "Execute solver plan",
                actions=guidance.execution_plan,
                expected_evidence=guidance.requested_evidence,
            )
            canonical_exp_id = canonical_exp.experiment_id
            state["active_experiment_id"] = canonical_exp_id

        for exp in guidance.experiments:
            ledger.append(exp)

        state_file.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")

        if guidance.validation_error:
            adv_status = "ERROR"
            adv_msg = f"Manual guidance JSON payload invalid: {guidance.validation_error}"
        else:
            adv_status = "READY"
            adv_msg = "Manual guidance imported and parsed successfully"

        return AdvisorResult(
            status=adv_status,
            guidance=guidance,
            provider="manual-import",
            message=adv_msg,
        )


    @staticmethod
    def parse_advisor_response(text: str) -> AdvisorGuidance:
        """Parse advisor markdown/text output into structured AdvisorGuidance."""
        return GuidanceParser.parse(text)

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

        # 1. Ghi nhận vào ExperimentLedger (Canonical History Writer)
        ledger = ExperimentLedger(advisor_dir)
        existing_exp = ledger.get(experiment_id)
        if existing_exp is None:
            raise UnknownExperimentError(
                f"ExecutionResult references unknown experiment '{experiment_id}'. Cannot evaluate or mutate hypotheses."
            )

        if isinstance(experiment_id_or_result, ExecutionResult):
            exec_res = experiment_id_or_result
        else:
            exec_res = ExecutionResult(
                experiment_id=experiment_id,
                status=status_clean if status_clean in ["CONFIRMED", "REJECTED", "INCONCLUSIVE", "FLAG_FOUND"] else "INCONCLUSIVE",
                observed=observed or "",
                evidence=[evidence] if evidence else [],
                stderr_tail=diff,
            )

        evaluation = EvidenceEvaluator.evaluate(existing_exp, exec_res)
        recorded_exp = ledger.record_result(
            experiment_id=experiment_id,
            evaluation=evaluation,
            execution_result=exec_res,
        )

        # 2. Cập nhật HypothesisManager
        hypo_mgr = HypothesisManager.load(advisor_dir / "hypotheses.json")
        target_hypo_id = existing_exp.hypothesis_id
        updated_hypo = hypo_mgr.apply_evaluation(target_hypo_id, evaluation)
        hypo_mgr.save(advisor_dir / "hypotheses.json")
        status_clean = evaluation.outcome.upper()

        # 3. Cập nhật DiscoveryTree (DAG Exploration Visualization)
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

        # 4. Quản lý Hypothesis Budget & Cắt Tỉa Nhánh Chết (Pruning)
        budget = state.setdefault("hypothesis_budget", {
            "max_failures_per_hypothesis": self.policy.stopping.get("max_consecutive_failures", 2),
            "current_failures": 0,
            "total_consultations": 0,
        })
        active_h = hypo_mgr.get_active()
        active_id = state.get("active_hypothesis_id") or (active_h.id if active_h else target_hypo_id)
        if not state.get("active_hypothesis_id") and active_id:
            state["active_hypothesis_id"] = active_id
            if active_h and not state.get("active_hypothesis"):
                state["active_hypothesis"] = active_h.statement

        is_active_target = (target_hypo_id == active_id)
        if is_active_target:
            budget["current_failures"] = updated_hypo.failure_count

        pivot_needed = False
        if status_clean == "REJECTED":
            if is_active_target and self.policy.branching.get("prune_dead_ends", True):
                recorder.tree.prune_subtree(act_node.node_id, reason=diff or observed)
                recorder.tree.save(recorder.tree_file)
                state["last_node_id"] = parent_node_id
            if is_active_target:
                pivot_needed = True
        elif status_clean == "INCONCLUSIVE":
            max_fails = budget.get("max_failures_per_hypothesis", 2)
            if is_active_target and (updated_hypo.failure_count >= max_fails or hypo_mgr.recommend_pivot()):
                pivot_needed = True
        elif status_clean in ["CONFIRMED", "FLAG_FOUND"]:
            if is_active_target:
                budget["current_failures"] = 0
                state["status"] = "testing_hypothesis"
                state["pivot_required"] = False
            act_node.status = "confirmed"
            obs_node.status = "confirmed"
            recorder.tree.save(recorder.tree_file)

        if pivot_needed:
            # Deterministic activation of registered proposed alternative hypothesis
            alternative = None
            for h in hypo_mgr.list_all():
                if h.id != target_hypo_id and h.status == "proposed":
                    alternative = h
                    break
            if alternative:
                hypo_mgr.activate(alternative.id)
                hypo_mgr.save(advisor_dir / "hypotheses.json")
                state["active_hypothesis"] = alternative.statement
                state["active_hypothesis_id"] = alternative.id
                state["pivot_required"] = False
                state["status"] = "testing_hypothesis"
                budget["current_failures"] = alternative.failure_count
                console.print(
                    f"[yellow]🔀 Pivoted active hypothesis to registered alternative {alternative.id}: {alternative.statement}[/yellow]"
                )
            else:
                state["pivot_required"] = True
                state["status"] = "stalled"
                console.print(
                    f"[bold red]🚨 HYPOTHESIS BUDGET EXCEEDED / REJECTED! Đã thất bại {budget['current_failures']} lần liên tiếp và không có giả thuyết thay thế.[/bold red]\n"
                    f"[yellow]Khuyến nghị: Chạy `./ctf advisor escalate {challenge_id}` để kích hoạt Strategic Assumption Challenge & Reframe![/yellow]"
                )

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
            "pivot_required": state.get("pivot_required", False),
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

    def escalate_strategic(self, challenge_id: Any, reason: str) -> Dict[str, Any]:
        """
        Strategic Assumption Challenge & Escalation Reframe:
        Chất vấn giả định hiện tại khi tiến trình bị bế tắc (tunnel vision).
        Đóng gói phản biện gửi lại cho Strategic Advisor để mở rộng không gian tìm kiếm.
        (Ghi chú trung thực: Đây là cơ chế reframe prompt chất vấn giả định,
         không phải multi-model consensus).
        """
        chall_dir = self._find_chall_dir(challenge_id)
        advisor_dir = chall_dir / ".advisor"
        state_file = advisor_dir / "state.json"
        state = json.loads(state_file.read_text(encoding="utf-8")) if state_file.exists() else {}

        name = state.get("challenge_name", f"Chall_{challenge_id}")
        active_hypo = state.get("active_hypothesis", "Chưa rõ")

        escalation_prompt = (
            f"### STRATEGIC ESCALATION REVIEW: CHALLENGE ASSUMPTIONS\n"
            f"Cơ chế chất vấn giả định chiến lược được kích hoạt cho bài: {name}\n"
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
            node_name="Strategic Assumption Escalation Review",
            payload={"reason": reason, "active_hypothesis": active_hypo},
            status="active",
        )

        state["escalated"] = True
        state["status"] = "investigating"
        state["last_node_id"] = esc_node.node_id
        state["hypothesis_budget"]["current_failures"] = 0
        state["last_updated"] = datetime.datetime.now().isoformat()
        state_file.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")

        console.print(f"[bold green]✔ Đã khởi tạo hồ sơ chất vấn chiến lược tại: {escalation_file.name}[/bold green]")
        console.print("[cyan]Đang gửi hồ sơ phản biện vào phiên làm việc của Strategic Advisor...[/cyan]")
        return self.consult(challenge_id, extra_instruction=escalation_prompt)

    def escalate_pal(self, challenge_id: Any, reason: str) -> Dict[str, Any]:
        """Backward-compatible alias for escalate_strategic."""
        return self.escalate_strategic(challenge_id, reason)

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
        table.add_row("Strategic Escalation", "✔ Có" if state.get("escalated") else "✖ Chưa")

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

