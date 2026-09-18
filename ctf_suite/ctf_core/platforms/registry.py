from typing import Callable, Dict, List, Optional, Type
import httpx
from .base import BasePlatform

PLATFORM_REGISTRY: Dict[str, Type[BasePlatform]] = {}
PLATFORM_MARKERS: Dict[str, List[str]] = {}
PLATFORM_COOKIE_HINTS: Dict[str, List[str]] = {}

def register_platform(
    name: str,
    markers: Optional[List[str]] = None,
    cookie_hints: Optional[List[str]] = None
):
    """Decorator đăng ký một Platform Adapter mới."""
    def decorator(cls: Type[BasePlatform]):
        key = name.lower()
        PLATFORM_REGISTRY[key] = cls
        if markers:
            PLATFORM_MARKERS[key] = markers
        if cookie_hints:
            PLATFORM_COOKIE_HINTS[key] = cookie_hints
        return cls
    return decorator

def detect_platform_type(
    url: str,
    session_cookie: Optional[str] = None
) -> str:
    """Tự động phát hiện loại platform dựa vào cookie và thăm dò HTML."""
    url_lower = url.lower()
    if "cyberhx.com" in url_lower or "nullorigin" in url_lower:
        return "cyberhx"

    cookie_str = session_cookie or ""
    
    # 1. Thăm dò bằng cookie hints
    for key, hints in PLATFORM_COOKIE_HINTS.items():
        if any(hint.lower() in cookie_str.lower() for hint in hints):
            return key

    # 2. Thăm dò bằng request HTML trang chủ
    try:
        with httpx.Client(timeout=10, follow_redirects=True) as client:
            # Thử probe API rCTF trước
            try:
                rctf_resp = client.get(f"{url.rstrip('/')}/api/v2/integrations/client/config")
                if rctf_resp.status_code == 200 and "goodClientConfig" in rctf_resp.text:
                    return "rctf"
            except Exception:
                pass

            # Thử probe API noCTF
            try:
                noctf_resp = client.get(f"{url.rstrip('/')}/site/config")
                if noctf_resp.status_code == 200 and "flag_prefix" in noctf_resp.text:
                    return "noctf"
            except Exception:
                pass

            resp = client.get(url)
            html = resp.text
            for key, markers in PLATFORM_MARKERS.items():
                if any(m.lower() in html.lower() for m in markers):
                    return key
    except Exception:
        pass

    # Mặc định rơi về ctfd vì là nền tảng phổ biến nhất
    return "ctfd"

def create_platform(
    platform_name: str,
    url: str,
    session_cookie: Optional[str] = None,
    api_token: Optional[str] = None,
    timeout: int = 30
) -> BasePlatform:
    key = platform_name.lower()
    if key not in PLATFORM_REGISTRY:
        raise ValueError(f"Platform không hỗ trợ: '{platform_name}'. Các platform hỗ trợ: {list(PLATFORM_REGISTRY.keys())}")
    cls = PLATFORM_REGISTRY[key]
    return cls(url=url, session_cookie=session_cookie, api_token=api_token, timeout=timeout)
