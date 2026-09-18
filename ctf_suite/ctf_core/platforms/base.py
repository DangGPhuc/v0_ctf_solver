from abc import ABC, abstractmethod
from typing import Any, List, Optional
import httpx
from ..models import CTFInfo, Challenge, ContainerInfo, SubmitResult

class BasePlatform(ABC):
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
        """Kiểm tra tính hợp lệ của cookie hoặc token."""
        pass

    @abstractmethod
    def fetch_challenges(self) -> List[Challenge]:
        """Lấy toàn bộ danh sách bài tập từ platform."""
        pass

    @abstractmethod
    def fetch_ctf_info(self) -> CTFInfo:
        """Lấy thông tin tổng quan của giải."""
        pass

    @abstractmethod
    def submit_flag(self, challenge_id: Any, flag: str) -> SubmitResult:
        """Nộp flag lên platform."""
        pass

    def start_instance(self, challenge_id: Any) -> ContainerInfo:
        """Khởi chạy dynamic container (nếu platform hỗ trợ)."""
        return ContainerInfo(status="error", message="Platform không hỗ trợ dynamic container")

    def stop_instance(self, challenge_id: Any) -> bool:
        """Dừng dynamic container."""
        return False

    def extend_instance(self, challenge_id: Any) -> bool:
        """Gia hạn thời gian chạy container."""
        return False

    def get_instance_status(self, challenge_id: Any) -> ContainerInfo:
        """Lấy trạng thái container hiện thời."""
        return ContainerInfo(status="stopped")
