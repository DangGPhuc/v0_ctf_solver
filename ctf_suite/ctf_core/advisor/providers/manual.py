from typing import Optional
from ...models import AdvisorResult
from .base import BaseAdvisorProvider


class ManualAdvisorProvider(BaseAdvisorProvider):
    """
    Fallback provider when no autonomous advisor is available.
    Pauses execution for manual human operator guidance.
    """

    def consult(
        self,
        prompt: str,
        oracle_session: Optional[str] = None,
        challenge_id: Optional[str] = None,
    ) -> AdvisorResult:
        return AdvisorResult(
            status="WAITING_FOR_MANUAL_RESPONSE",
            provider="manual",
            message="Chờ phản hồi thủ công từ người dùng qua Web UI / Firefox.",
        )
