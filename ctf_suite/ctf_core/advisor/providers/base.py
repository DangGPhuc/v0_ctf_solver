from abc import ABC, abstractmethod
from typing import Optional
from ...models import AdvisorResult


class BaseAdvisorProvider(ABC):
    """Abstract interface for Strategic Advisor backend providers."""

    @abstractmethod
    def consult(
        self,
        prompt: str,
        oracle_session: Optional[str] = None,
        challenge_id: Optional[str] = None,
    ) -> AdvisorResult:
        """Sends compiled prompt to strategic advisor and returns parsed AdvisorResult."""
        pass
