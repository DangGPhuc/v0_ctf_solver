from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, List, Optional
import httpx
from ..models import CTFInfo, Challenge, ContainerInfo, SubmitResult

class BasePlatform(ABC):
    """
    Standard thin PlatformAdapter abstraction across CTFd, CyberHX, GZCTF, rCTF, noCTF.
    Responsible solely for translating platform-specific APIs into standardized models.
    Does NOT manage filesystem workspaces, solvers, or credentials persistence.
    """
    def __init__(
        self,
        url: str,
        session_cookie: Optional[str] = None,
        api_token: Optional[str] = None,
        timeout: int = 30
    ):
        self.url = url.rstrip("/")
        self.session_cookie = session_cookie
        self.api_token = api_token
        self.timeout = timeout
        
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
            "Accept": "application/json, text/html, */*",
        }
        if self.session_cookie:
            headers["Cookie"] = self.session_cookie
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"
            
        self.client = httpx.Client(
            base_url=self.url,
            headers=headers,
            timeout=self.timeout,
            follow_redirects=True
        )

    def close(self):
        self.client.close()

    @abstractmethod
    def authenticate(self) -> bool:
        """Verify session cookie or API token validity."""
        pass

    @abstractmethod
    def fetch_challenges(self) -> List[Challenge]:
        """Fetch all challenges from platform."""
        pass

    def list_challenges(self) -> List[Challenge]:
        """Standard method alias for fetch_challenges."""
        return self.fetch_challenges()

    @abstractmethod
    def fetch_ctf_info(self) -> CTFInfo:
        """Fetch competition/event summary metadata."""
        pass

    def get_event_info(self) -> CTFInfo:
        """Standard method alias for fetch_ctf_info."""
        return self.fetch_ctf_info()

    def get_challenge(self, challenge_id: Any) -> Optional[Challenge]:
        """Retrieve single challenge metadata by ID."""
        cid_str = str(challenge_id).strip().lower()
        for ch in self.list_challenges():
            if str(ch.id).strip().lower() == cid_str or ch.name.strip().lower() == cid_str:
                return ch
        return None

    def download_attachments(self, challenge_id: Any, destination: Path) -> List[Path]:
        """Download attachments for a single challenge using origin-isolated downloader."""
        from ..downloaders.manager import DownloadManager
        chall = self.get_challenge(challenge_id)
        if not chall or not chall.files:
            return []
        
        dm = DownloadManager(
            platform_url=self.url,
            session_cookie=self.session_cookie,
            api_token=self.api_token,
            timeout=self.timeout
        )
        try:
            return dm.download_attachments(chall.files, destination)
        finally:
            dm.close()

    @abstractmethod
    def submit_flag(self, challenge_id: Any, flag: str) -> SubmitResult:
        """Submit a flag candidate to the platform."""
        pass

    def start_instance(self, challenge_id: Any) -> ContainerInfo:
        """Start dynamic container (if platform supports it)."""
        return ContainerInfo(status="error", message="Platform does not support dynamic containers")

    def stop_instance(self, challenge_id: Any) -> bool:
        """Stop dynamic container."""
        return False

    def extend_instance(self, challenge_id: Any) -> bool:
        """Extend running container duration."""
        return False

    def get_instance_status(self, challenge_id: Any) -> ContainerInfo:
        """Get current container status."""
        return ContainerInfo(status="stopped")

PlatformAdapter = BasePlatform
