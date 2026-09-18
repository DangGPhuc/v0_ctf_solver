import re
from typing import Any, Dict, List, Optional
from ..models import CTFInfo, Challenge, ContainerInfo, SubmitResult, SubmitVerdict
from .base import BasePlatform
from .registry import register_platform

@register_platform(
    name="gzctf",
    markers=["GZCTF", "GZ::CTF", "/api/game/"],
    cookie_hints=["GZCTF_Token"]
)
class GZCTFPlatform(BasePlatform):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.game_id: Optional[str] = self._extract_game_id_from_url(self.url)
        self._user_profile: Dict[str, Any] = {}

    def _extract_game_id_from_url(self, url: str) -> Optional[str]:
        m = re.search(r'/games?/([0-9a-fA-F\-]+)', url)
        return m.group(1) if m else None

    def _ensure_game_id(self) -> Optional[str]:
        if self.game_id:
            return self.game_id
        # Thử lấy danh sách game từ API
        try:
            resp = self.client.get("/api/game")
            if resp.status_code == 200:
                games = resp.json()
                if isinstance(games, list) and len(games) > 0:
                    self.game_id = str(games[0].get("id"))
                    return self.game_id
        except Exception:
            pass
        return None

    def authenticate(self) -> bool:
        try:
            resp = self.client.get("/api/account/profile")
            if resp.status_code == 200:
                self._user_profile = resp.json()
                return True
        except Exception:
            pass
        return False

    def fetch_ctf_info(self) -> CTFInfo:
        self._ensure_game_id()
        title = "GZCTF Competition"
        if self.game_id:
            try:
                resp = self.client.get(f"/api/game/{self.game_id}")
                if resp.status_code == 200:
                    title = resp.json().get("title", title)
            except Exception:
                pass

        user_name = self._user_profile.get("userName")
        team_name = None
        teams = self._user_profile.get("teams", [])
        if teams and isinstance(teams, list):
            team_name = teams[0].get("teamName")

        return CTFInfo(
            title=title,
            platform="gzctf",
            url=self.url,
            user_name=user_name,
            team_name=team_name
        )

    def fetch_challenges(self) -> List[Challenge]:
        gid = self._ensure_game_id()
        if not gid:
            return []

        challenges: List[Challenge] = []
        resp = self.client.get(f"/api/game/{gid}/challenges")
        if resp.status_code != 200:
            return challenges

        items = resp.json()
        if not isinstance(items, list):
            return challenges

        for item in items:
            cid = item.get("id")
            # Fetch chi tiết từng bài
            detail_resp = self.client.get(f"/api/game/{gid}/challenges/{cid}")
            detail_data = item
            if detail_resp.status_code == 200:
                detail_data = detail_resp.json()

            files_list = []
            for f in detail_data.get("attachments", []):
                fname = f.get("name", "attachment")
                furl = f.get("url", "")
                if furl and not furl.startswith("http"):
                    furl = f"{self.url}{furl}"
                files_list.append({"name": fname, "url": furl})

            chall = Challenge(
                id=cid,
                name=detail_data.get("title", f"chall_{cid}"),
                category=detail_data.get("category", "Misc"),
                points=detail_data.get("score") or detail_data.get("points", 0),
                description=detail_data.get("content", ""),
                author=detail_data.get("author"),
                tags=detail_data.get("tag") or [],
                hints=detail_data.get("hints", []),
                files=files_list,
                connection_info=detail_data.get("connectionInfo"),
                solved_by_me=detail_data.get("solved", False),
                solves_count=detail_data.get("solvedCount"),
                is_dynamic_container=bool(detail_data.get("type") in ["DynamicContainer", "Container"]),
                raw_data=detail_data
            )
            challenges.append(chall)
        return challenges

    def submit_flag(self, challenge_id: Any, flag: str) -> SubmitResult:
        gid = self._ensure_game_id()
        if not gid:
            return SubmitResult(
                verdict="error",
                message="Không xác định được game_id của GZCTF.",
                challenge_id=challenge_id,
                flag=flag
            )

        payload = {"flag": flag.strip()}
        try:
            resp = self.client.post(f"/api/game/{gid}/challenges/{challenge_id}/submit", json=payload)
            if resp.status_code == 429:
                return SubmitResult(
                    verdict="ratelimited",
                    message="Bị giới hạn tốc độ (Rate Limited) từ GZCTF.",
                    challenge_id=challenge_id,
                    flag=flag
                )
            if resp.status_code == 401 or resp.status_code == 403:
                return SubmitResult(
                    verdict="auth_failed",
                    message="GZCTF_Token hết hạn hoặc không có quyền nộp.",
                    challenge_id=challenge_id,
                    flag=flag
                )
            if resp.status_code in [200, 204]:
                # GZCTF trả 200 kèm JSON kết quả hoặc status
                data = resp.json() if resp.text else {}
                msg = data.get("message", "Nộp flag thành công!")
                return SubmitResult(
                    verdict="correct",
                    message=msg,
                    challenge_id=challenge_id,
                    flag=flag
                )
            # Nếu trả về mã lỗi thông thường (400)
            data = resp.json() if resp.text else {}
            msg = data.get("message", "Flag không chính xác.")
            return SubmitResult(
                verdict="incorrect",
                message=msg,
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
        gid = self._ensure_game_id()
        if not gid:
            return ContainerInfo(status="error", message="Thiếu game_id")
        try:
            resp = self.client.post(f"/api/game/{gid}/challenges/{challenge_id}/container")
            if resp.status_code in [200, 201]:
                data = resp.json()
                entry = data.get("entry")
                host = None
                port = None
                if entry and ":" in entry:
                    parts = entry.split(":")
                    host = parts[0]
                    try:
                        port = int(parts[1])
                    except ValueError:
                        pass
                return ContainerInfo(
                    status="running",
                    entry=entry,
                    host=host,
                    port=port,
                    remaining_seconds=data.get("remain"),
                    raw=data
                )
            return ContainerInfo(status="error", message=f"Khởi động thất bại ({resp.status_code}): {resp.text[:100]}")
        except Exception as e:
            return ContainerInfo(status="error", message=str(e))

    def stop_instance(self, challenge_id: Any) -> bool:
        gid = self._ensure_game_id()
        if not gid:
            return False
        try:
            resp = self.client.delete(f"/api/game/{gid}/challenges/{challenge_id}/container")
            return resp.status_code in [200, 204]
        except Exception:
            return False

    def extend_instance(self, challenge_id: Any) -> bool:
        gid = self._ensure_game_id()
        if not gid:
            return False
        try:
            resp = self.client.put(f"/api/game/{gid}/challenges/{challenge_id}/container")
            return resp.status_code in [200, 204]
        except Exception:
            return False
