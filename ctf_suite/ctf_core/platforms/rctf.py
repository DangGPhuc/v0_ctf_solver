import re
import urllib.parse
from typing import Any, Dict, List, Optional
import httpx

from ..models import CTFInfo, Challenge, ContainerInfo, SubmitResult, SubmitVerdict
from .base import BasePlatform
from .registry import register_platform

@register_platform(
    name="rctf",
    markers=["rCTF", "NNS CTF", "/api/v2/challs", "goodClientConfig", "goodUserSelfDataV2"],
    cookie_hints=["token="]
)
class RCTFPlatform(BasePlatform):
    """
    Platform Adapter cho hệ thống rCTF (v1 / v2 API)
    Đặc biệt hỗ trợ NNS CTF và các giải sử dụng rCTF.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._user_info: Dict[str, Any] = {}
        self._client_config: Dict[str, Any] = {}
        self._solves_set: set = set()

    def authenticate(self) -> bool:
        """Kiểm tra token bằng /api/v2/users/me."""
        try:
            resp = self.client.get("/api/v2/users/me")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("kind") in ["goodUserSelfDataV2", "goodUserData"]:
                    self._user_info = data.get("data", {})
                    # Lấy danh sách challenge id đã solve
                    solves = self._user_info.get("solves", [])
                    self._solves_set = {s.get("id") for s in solves if isinstance(s, dict)}
                    return True
        except Exception:
            pass
        return False

    def _fetch_client_config(self) -> Dict[str, Any]:
        if self._client_config:
            return self._client_config
        try:
            resp = self.client.get("/api/v2/integrations/client/config")
            if resp.status_code == 200:
                self._client_config = resp.json().get("data", {})
        except Exception:
            pass
        return self._client_config

    def fetch_ctf_info(self) -> CTFInfo:
        config = self._fetch_client_config()
        title = config.get("ctfName") or "rCTF Competition"
        flag_placeholder = config.get("flagFormatPlaceholder")
        flag_format = None
        if flag_placeholder:
            # Ví dụ: NNS{...} -> r"^NNS\{.+\}$"
            prefix = flag_placeholder.split("{")[0]
            if prefix:
                flag_format = f"^{re.escape(prefix)}\\{{.+?\\}}$"

        user_name = self._user_info.get("name")
        team_name = self._user_info.get("name")

        return CTFInfo(
            title=title,
            platform="rctf",
            url=self.url,
            user_name=user_name,
            team_name=team_name,
            flag_format=flag_format
        )

    def fetch_challenges(self) -> List[Challenge]:
        challenges: List[Challenge] = []
        try:
            resp = self.client.get("/api/v2/challs")
            if resp.status_code != 200:
                return challenges
            
            body = resp.json()
            if body.get("kind") not in ["goodChallenges", "goodChallengesV2"]:
                return challenges
                
            items = body.get("data", [])
        except Exception:
            return challenges

        for item in items:
            cid = item.get("id")
            files_list = []
            for f in item.get("files", []):
                fname = f.get("name")
                furl = f.get("url", "")
                if not fname:
                    fname = furl.split("/")[-1].split("?")[0] or "attachment"
                files_list.append({"name": fname, "url": furl})

            has_instancer = item.get("instancerLifetime") is not None

            chall = Challenge(
                id=cid,
                name=item.get("name", f"chall_{cid}"),
                category=item.get("category", "Misc"),
                points=item.get("points", 0),
                description=item.get("description", ""),
                author=item.get("author"),
                tags=item.get("tags") or [],
                hints=[],
                files=files_list,
                connection_info=None,
                solved_by_me=(cid in self._solves_set),
                solves_count=item.get("solves"),
                is_dynamic_container=has_instancer,
                raw_data=item
            )
            challenges.append(chall)

        return challenges

    def submit_flag(self, challenge_id: Any, flag: str) -> SubmitResult:
        encoded_id = urllib.parse.quote(str(challenge_id))
        payload = {"flag": flag.strip()}
        try:
            resp = self.client.post(f"/api/v1/challs/{encoded_id}/submit", json=payload)
            if resp.status_code == 429:
                return SubmitResult(
                    verdict="ratelimited",
                    message="Bị giới hạn tốc độ (Rate Limited) từ rCTF.",
                    challenge_id=challenge_id,
                    flag=flag
                )
            if resp.status_code in [401, 403]:
                return SubmitResult(
                    verdict="auth_failed",
                    message="Token xác thực không hợp lệ hoặc hết hạn.",
                    challenge_id=challenge_id,
                    flag=flag
                )

            body = resp.json() if resp.text else {}
            kind = body.get("kind", "")
            msg = body.get("message", kind)

            if kind == "goodFlag":
                return SubmitResult(
                    verdict="correct",
                    message=msg or "Flag chính xác! Điểm đã được cộng.",
                    challenge_id=challenge_id,
                    flag=flag
                )
            elif kind == "alreadySolved":
                return SubmitResult(
                    verdict="already_solved",
                    message=msg or "Bài này bạn đã giải trước đó rồi.",
                    challenge_id=challenge_id,
                    flag=flag
                )
            elif kind == "badFlag":
                return SubmitResult(
                    verdict="incorrect",
                    message=msg or "Flag không chính xác.",
                    challenge_id=challenge_id,
                    flag=flag
                )
            elif kind == "badRateLimit":
                return SubmitResult(
                    verdict="ratelimited",
                    message=msg or "Rate limited.",
                    challenge_id=challenge_id,
                    flag=flag
                )
            else:
                return SubmitResult(
                    verdict="error",
                    message=f"{kind}: {msg}",
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

    def get_instance_status(self, challenge_id: Any) -> ContainerInfo:
        encoded_id = urllib.parse.quote(str(challenge_id))
        try:
            resp = self.client.get(f"/api/v2/integrations/challs/{encoded_id}/instance")
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                status = data.get("status", "stopped")
                endpoints = data.get("endpoints", [])
                entry = None
                host = None
                port = None
                if endpoints:
                    first_ep = endpoints[0]
                    host = first_ep.get("host")
                    port = first_ep.get("port")
                    if host and port:
                        entry = f"{host}:{port}"
                    else:
                        entry = first_ep.get("url")
                        if entry and ":" in entry:
                            parts = entry.split(":")
                            host = parts[0]
                            try:
                                port = int(parts[1])
                            except ValueError:
                                pass
                return ContainerInfo(
                    status="running" if status == "running" else status,
                    entry=entry,
                    host=host,
                    port=port,
                    remaining_seconds=data.get("timeLeftMilliseconds", 0) // 1000 if data.get("timeLeftMilliseconds") else None,
                    raw=data
                )
            return ContainerInfo(status="stopped")
        except Exception as e:
            return ContainerInfo(status="error", message=str(e))

    def start_instance(self, challenge_id: Any) -> ContainerInfo:
        encoded_id = urllib.parse.quote(str(challenge_id))
        try:
            resp = self.client.put(f"/api/v2/integrations/challs/{encoded_id}/instance", json={})
            if resp.status_code == 200:
                body = resp.json()
                if body.get("kind") == "goodInstanceStatus":
                    import time
                    for _ in range(45):
                        status_info = self.get_instance_status(challenge_id)
                        if status_info.status == "running":
                            return status_info
                        time.sleep(1)
                    return self.get_instance_status(challenge_id)
            return ContainerInfo(
                status="error",
                message=f"Không thể khởi động container: {resp.status_code} - {resp.text[:120]}"
            )
        except Exception as e:
            return ContainerInfo(status="error", message=str(e))

    def stop_instance(self, challenge_id: Any) -> bool:
        encoded_id = urllib.parse.quote(str(challenge_id))
        try:
            resp = self.client.delete(f"/api/v2/integrations/challs/{encoded_id}/instance")
            return resp.status_code == 200
        except Exception:
            return False

    def extend_instance(self, challenge_id: Any) -> bool:
        encoded_id = urllib.parse.quote(str(challenge_id))
        try:
            resp = self.client.patch(f"/api/v2/integrations/challs/{encoded_id}/instance", json={})
            return resp.status_code == 200
        except Exception:
            return False
