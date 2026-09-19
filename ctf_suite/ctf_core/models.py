from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

SubmitVerdict = Literal[
    "correct",
    "incorrect",
    "already_solved",
    "ratelimited",
    "auth_failed",
    "invalid_format",
    "error",
]

class ContainerInfo(BaseModel):
    status: str = "stopped"  # running, stopped, expired, error
    entry: Optional[str] = None  # e.g. "chall.ctf.com:31337" or "http://chall.ctf.com:8080"
    host: Optional[str] = None
    port: Optional[int] = None
    remaining_seconds: Optional[int] = None
    message: Optional[str] = None
    raw: Dict[str, Any] = Field(default_factory=dict)

class SubmitResult(BaseModel):
    verdict: SubmitVerdict
    message: str
    challenge_id: Any
    challenge_name: Optional[str] = None
    flag: str
    points: Optional[int] = None
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())

    @property
    def status(self) -> str:
        return str(self.verdict)


class Challenge(BaseModel):
    id: Any
    name: str
    category: str = "Misc"
    points: int = 0
    description: str = ""
    author: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    hints: List[Dict[str, Any]] = Field(default_factory=list)
    files: List[Dict[str, str]] = Field(default_factory=list)  # [{"name": "chall.zip", "url": "..."}]
    connection_info: Optional[str] = None
    solved_by_me: bool = False
    solves_count: Optional[int] = None
    is_dynamic_container: bool = False
    instance_info: Optional[ContainerInfo] = None
    raw_data: Dict[str, Any] = Field(default_factory=dict)

class CTFInfo(BaseModel):
    title: str = "CTF Competition"
    description: str = ""
    platform: str = "generic"
    url: str = ""
    user_name: Optional[str] = None
    team_name: Optional[str] = None
    flag_format: Optional[str] = None
    challenges: List[Challenge] = Field(default_factory=list)

# ==============================================================================
# STRUCTURED ADVISOR & CLOSED-LOOP EXECUTOR MODELS
# ==============================================================================

class Hypothesis(BaseModel):
    id: str = "H1"
    statement: str
    confidence: float = 0.5
    rationale: str = ""
    status: Literal[
        "proposed",
        "active",
        "confirmed",
        "rejected",
        "inconclusive",
    ] = "proposed"
    attempts: int = 0
    failure_count: int = 0
    supporting_evidence: List[str] = Field(default_factory=list)
    contradicting_evidence: List[str] = Field(default_factory=list)

HypothesisRecord = Hypothesis

class ExecutionAction(BaseModel):
    kind: Literal[
        "run_solver",
        "run_python_file",
        "run_sage_file",
        "run_binary",
        "read_file",
        "list_files",
        "analysis_tool",
    ] = "run_solver"
    argv: List[str] = Field(default_factory=list)
    path: Optional[str] = None
    tool: Optional[str] = None
    timeout: int = 60

class ExperimentEvaluation(BaseModel):
    outcome: Literal[
        "confirmed",
        "rejected",
        "inconclusive",
        "flag_found",
    ]
    supporting_evidence: List[str] = Field(default_factory=list)
    contradicting_evidence: List[str] = Field(default_factory=list)
    reason: str = ""

class Experiment(BaseModel):
    experiment_id: str
    hypothesis_id: str
    intent: str
    action: Optional[ExecutionAction] = None
    execution_plan: List[ExecutionAction] = Field(default_factory=list)
    expected_evidence: List[str] = Field(default_factory=list)
    contradicting_evidence: List[str] = Field(default_factory=list)
    actual_evidence: List[str] = Field(default_factory=list)
    outcome: Literal[
        "pending",
        "confirmed",
        "rejected",
        "inconclusive",
        "failed",
        "flag_found",
    ] = "pending"
    reason: str = ""
    created_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    completed_at: Optional[str] = None

    @property
    def actions_to_run(self) -> List[ExecutionAction]:
        if self.execution_plan:
            return list(self.execution_plan)
        if self.action:
            return [self.action]
        return []

class Action(BaseModel):
    type: str = "command"
    command_or_task: str
    expected_evidence: str = ""

class AdvisorGuidance(BaseModel):
    assessment: str = ""
    hypotheses: List[Hypothesis] = Field(default_factory=list)
    experiments: List[Experiment] = Field(default_factory=list)
    execution_plan: List[ExecutionAction] = Field(default_factory=list)
    next_actions: List[Action] = Field(default_factory=list)
    requested_evidence: List[str] = Field(default_factory=list)
    stop_conditions: List[str] = Field(default_factory=list)
    raw_text: Optional[str] = None
    validation_error: Optional[str] = None
    is_structured: bool = False

class AdvisorResult(BaseModel):
    status: Literal[
        "READY",
        "WAITING_FOR_MANUAL_RESPONSE",
        "PROVIDER_UNAVAILABLE",
        "ERROR",
    ]
    guidance: Optional[AdvisorGuidance] = None
    provider: str = "oracle"
    message: str = ""
    session_id: Optional[str] = None
    raw_response: Optional[str] = None

class ExecutionResult(BaseModel):
    experiment_id: str
    status: Literal[
        "CONFIRMED",
        "REJECTED",
        "INCONCLUSIVE",
        "FLAG_FOUND",
        "ERROR",
    ]
    return_code: Optional[int] = None
    actions: List[str] = Field(default_factory=list)
    observed: str = ""
    evidence: List[str] = Field(default_factory=list)
    flag_candidates: List[str] = Field(default_factory=list)
    stdout_tail: Optional[str] = None
    stderr_tail: Optional[str] = None

# ==============================================================================
# KNOWLEDGE CARD SCHEMA (DISTILLED MEMORY - NO REAL FLAGS/CREDS)
# ==============================================================================

class KnowledgeCardFingerprint(BaseModel):
    file_types: List[str] = Field(default_factory=list)
    protections: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)

class KnowledgeCardSource(BaseModel):
    challenge_hash: str = ""
    learned_at: str = Field(default_factory=lambda: datetime.now().isoformat())

class KnowledgeCard(BaseModel):
    id: str
    title: str
    category: str
    fingerprint: KnowledgeCardFingerprint = Field(default_factory=KnowledgeCardFingerprint)
    signals: List[str] = Field(default_factory=list)
    primitive: str = ""
    preconditions: List[str] = Field(default_factory=list)
    strategy: List[str] = Field(default_factory=list)
    verification: List[str] = Field(default_factory=list)
    failure_modes: List[str] = Field(default_factory=list)
    reusable_snippets: List[str] = Field(default_factory=list)
    source: KnowledgeCardSource = Field(default_factory=KnowledgeCardSource)


class ChallengeFingerprint(BaseModel):
    category: str = "misc"
    subcategory: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    file_types: List[str] = Field(default_factory=list)
    architectures: List[str] = Field(default_factory=list)
    frameworks: List[str] = Field(default_factory=list)
    protections: List[str] = Field(default_factory=list)
    primitives: List[str] = Field(default_factory=list)
    suspicious_patterns: List[str] = Field(default_factory=list)
    runtime_signals: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = 0.5

    def to_knowledge_query(self, hypothesis: Optional[str] = None):
        from ctf_core.knowledge.models import KnowledgeQuery
        all_tags = list(self.tags)
        for t in self.architectures + self.frameworks + self.primitives:
            if t and t not in all_tags:
                all_tags.append(t)
        return KnowledgeQuery(
            category=self.category,
            tags=all_tags,
            file_types=self.file_types,
            protections=self.protections,
            keywords=self.suspicious_patterns,
            current_hypothesis=hypothesis,
        )


