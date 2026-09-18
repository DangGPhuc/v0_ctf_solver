import re
from typing import Any, Dict, List, Optional
import httpx
from ..models import CTFInfo, Challenge, ContainerInfo, SubmitResult, SubmitVerdict
from .base import BasePlatform
from .registry import register_platform

@register_platform(
    name="ctfd",
    markers=["CTFd", "/api/v1/challenges", "csrfNonce"],
    cookie_hints=["session="]
)
class CTFdPlatform(BasePlatform):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.csrf_nonce: Optional[str] = None
        self._user_info: Dict[str, Any] = {}

    def _ensure_csrf(self) -> Optional[str]:
        if self.csrf_nonce:
            return self.csrf_nonce
        try:
            resp = self.client.get("/challenges")
            if resp.status_code == 200:
                # Tìm csrfNonce trong script hoặc meta
                m = re.search(r'["\']csrfNonce["\']\s*:\s*["\']([a-fA-F0-9]+)["\']', resp.text)
                if not m:
                    m = re.search(r'name=["\']nonce["\']\s+value=["\']([a-fA-F0-9]+)["\']', resp.text)
                if m:
                    self.csrf_nonce = m.group(1)
                    self.client.headers["CSRF-Token"] = self.csrf_nonce
                    return self.csrf_nonce
        except Exception:
            pass
        return None

    def authenticate(self) -> bool:
        self._ensure_csrf()
        try:
            resp = self.client.get("/api/v1/users/me")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("success"):
                    self._user_info = data.get("data", {})
                    return True
        except Exception:
            pass
        return False

    def fetch_ctf_info(self) -> CTFInfo:
        title = "CTFd Competition"
        try:
            resp = self.client.get("/")
            if resp.status_code == 200:
                m = re.search(r'<title>(.*?)</title>', resp.text, re.IGNORECASE)
                if m:
                    title = m.group(1).split("—")[0].split("-")[0].strip()
        except Exception:
            pass

        user_name = self._user_info.get("name")
        team_id = self._user_info.get("team_id")
        team_name = None
        if team_id:
            try:
                t_resp = self.client.get(f"/api/v1/teams/{team_id}")
                if t_resp.status_code == 200:
                    team_name = t_resp.json().get("data", {}).get("name")
            except Exception:
                pass

        return CTFInfo(
            title=title,
            platform="ctfd",
            url=self.url,
            user_name=user_name,
            team_name=team_name
        )

    def fetch_challenges(self) -> List[Challenge]:
        challenges: List[Challenge] = []
        resp = self.client.get("/api/v1/challenges")
        if resp.status_code != 200:
            return challenges

        items = resp.json().get("data", [])
        for item in items:
            cid = item.get("id")
            # Fetch chi tiết từng bài
            detail_resp = self.client.get(f"/api/v1/challenges/{cid}")
            detail_data = item
            if detail_resp.status_code == 200:
                detail_data = detail_resp.json().get("data", item)

            files_list = []
            for f in detail_data.get("files", []):
                # f có thể là URL hoặc relative path
                furl = f if f.startswith("http") else f"{self.url}{f}"
                fname = furl.split("/")[-1].split("?")[0]
                files_list.append({"name": fname, "url": furl})

            chall = Challenge(
                id=cid,
                name=detail_data.get("name", f"chall_{cid}"),
                category=detail_data.get("category", "Misc"),
                points=detail_data.get("value", 0),
                description=detail_data.get("description", ""),
                author=detail_data.get("attribution") or detail_data.get("author"),
                tags=[t.get("value", str(t)) if isinstance(t, dict) else str(t) for t in detail_data.get("tags", [])],
                hints=detail_data.get("hints", []),
                files=files_list,
                connection_info=detail_data.get("connection_info"),
                solved_by_me=detail_data.get("solved_by_me", False),
                solves_count=detail_data.get("solves"),
                is_dynamic_container=(
                    detail_data.get("type") in ["container", "dynamic_docker", "whale"] or
                    "container" in detail_data or "whale" in detail_data
                ),
                raw_data=detail_data
            )
            challenges.append(chall)
        return challenges

    def submit_flag(self, challenge_id: Any, flag: str) -> SubmitResult:
        self._ensure_csrf()
        payload = {
            "challenge_id": challenge_id,
            "submission": flag.strip()
        }
        try:
            resp = self.client.post("/api/v1/challenges/attempt", json=payload)
            if resp.status_code == 429:
                return SubmitResult(
                    verdict="ratelimited",
                    message="Bị giới hạn tốc độ (Rate Limited) từ CTFd.",
                    challenge_id=challenge_id,
                    flag=flag
                )
            if resp.status_code == 403:
                return SubmitResult(
                    verdict="auth_failed",
                    message="Cookie hoặc CSRF Token hết hạn.",
                    challenge_id=challenge_id,
                    flag=flag
                )
            if resp.status_code == 200:
                body = resp.json()
                status = body.get("data", {}).get("status", "")
                msg = body.get("data", {}).get("message", status)
                
                verdict: SubmitVerdict = "incorrect"
                if status == "correct":
                    verdict = "correct"
                elif status == "already_solved":
                    verdict = "already_solved"
                elif status == "paused":
                    verdict = "error"
                    
                return SubmitResult(
                    verdict=verdict,
                    message=msg,
                    challenge_id=challenge_id,
                    flag=flag
                )
            return SubmitResult(
                verdict="error",
                message=f"HTTP {resp.status_code}: {resp.text[:100]}",
                challenge_id=challenge_id,
                flag=flag
            )
        except Exception as e:
            return SubmitResult(
                verdict="error",
                message=str(e),
                challenge_id=challenge_id,
                flag=flag
            )

    def start_instance(self, challenge_id: Any) -> ContainerInfo:
        self._ensure_csrf()
        # Thử endpoint CTFd Whale plugin
        whale_url = f"/plugins/ctfd-whale/container?challenge_id={challenge_id}"
        try:
            resp = self.client.post(whale_url)
            if resp.status_code in [200, 201]:
                data = resp.json()
                host = data.get("host")
                port = data.get("port")
                entry = f"{host}:{port}" if host and port else data.get("entry")
                return ContainerInfo(
                    status="running",
                    entry=entry,
                    host=host,
                    port=port,
                    remaining_seconds=data.get("remaining_time"),
                    raw=data
                )
            return ContainerInfo(
                status="error",
                message=f"Khởi động container thất bại ({resp.status_code}): {resp.text[:100]}"
            )
        except Exception as e:
            return ContainerInfo(status="error", message=str(e))

    def stop_instance(self, challenge_id: Any) -> bool:
        self._ensure_csrf()
        try:
            resp = self.client.delete(f"/plugins/ctfd-whale/container?challenge_id={challenge_id}")
            return resp.status_code in [200, 204]
        except Exception:
            return False

    def extend_instance(self, challenge_id: Any) -> bool:
        self._ensure_csrf()
        try:
            resp = self.client.post(f"/plugins/ctfd-whale/container?challenge_id={challenge_id}&action=renew")
            return resp.status_code == 200
        except Exception:
            return False
