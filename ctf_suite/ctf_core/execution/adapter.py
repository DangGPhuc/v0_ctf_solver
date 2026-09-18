from typing import Any, Dict, Protocol
from ..models import AdvisorGuidance, ExecutionResult

class ExecutorAdapter(Protocol):
    """
    Protocol for Closed-Loop Execution Adapters (Anti-IDE / OpenCode / Local subprocess).
    Consumes structured AdvisorGuidance and produces an auditable ExecutionResult.
    """
    def execute(
        self,
        challenge_context: Dict[str, Any],
        guidance: AdvisorGuidance,
    ) -> ExecutionResult:
        ...
