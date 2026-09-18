import urllib.parse
from typing import Any, Dict, List, Optional
import httpx

from ..models import CTFInfo, Challenge, ContainerInfo, SubmitResult
from .base import BasePlatform
from .registry import register_platform

@register_platform(
    name="noctf",
    markers=["noctf", "k17 ctf", "api-k17ctf", "scoreboard.k17ctf", "instrument sans"],
    cookie_hints=[]
)
class NoCTFPlatform(BasePlatform):
    """
    Platform Adapter cho nền tảng noCTF (Fastify backend + SvelteKit frontend).
    Hỗ trợ K17 CTF và các giải sử dụng noCTF.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._user_info: Dict[str, Any] = {}
        self._site_config: Dict[str, Any] = {}
        # Bổ sung headers Origin / Referer cần thiết
        self.client.headers.update({
            "Origin": "https://scoreboard.k17ctf.secso.cc",
            "Referer": "https://scoreboard.k17ctf.secso.cc/",
        })

    def authenticate(self) -> bool:
        """Kiểm tra token bằng GET /user/me."""
        try:
            resp = self.client.get("/user/me")
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                if data and "id" in data:
                    self._user_info = data
                    return True
        except Exception:
            pass
        return False

    def _fetch_site_config(self) -> Dict[str, Any]:
        if self._site_config:
            return self._site_config
        try:
            resp = self.client.get("/site/config")
            if resp.status_code == 200:
                self._site_config = resp.json().get("data", {})
        except Exception:
            pass
        return self._site_config

    def fetch_ctf_info(self) -> CTFInfo:
        config = self._fetch_site_config()
        title = config.get("name") or "noCTF Competition"
        flag_prefix = config.get("flag_prefix", "FLAG")
        flag_format = f"^{flag_prefix}\\{{.+?\\}}$"

        if not self._user_info:
            self.authenticate()

        user_name = self._user_info.get("name")
        team_name = self._user_info.get("team_name")

        return CTFInfo(
            title=title,
            platform="noctf",
            url=self.url,
            user_name=user_name,
            team_name=team_name,
            flag_format=flag_format
        )

    def fetch_challenges(self) -> List[Challenge]:
        challenges: List[Challenge] = []
        try:
            resp = self.client.get("/challenges")
            if resp.status_code != 200:
                return challenges
            
            data = resp.json().get("data", {})
            items = data.get("challenges", [])
        except Exception:
            return challenges

        for item in items:
            cid = item.get("id")
            slug = item.get("slug", f"chall_{cid}")
            title = item.get("title", slug)
            tags_dict = item.get("tags") or {}
            category = tags_dict.get("categories", "Misc")
            # Nếu category có dấu phẩy, lấy category đầu tiên
            main_cat = category.split(",")[0].strip().title()

            # Lấy chi tiết challenge để có description và files
            files_list = []
            description = ""
            try:
                detail_resp = self.client.get(f"/challenges/{cid}")
                if detail_resp.status_code == 200:
                    detail_data = detail_resp.json().get("data", {})
                    description = detail_data.get("description", "")
                    meta = detail_data.get("metadata", {})
                    raw_files = meta.get("files", [])
                    for f in raw_files:
                        fname = f.get("filename") or "attachment"
                        furl = f.get("url", "")
                        if furl and not furl.startswith("http"):
                            furl = f"{self.url.rstrip('/')}/{furl.lstrip('/')}"
                        files_list.append({"name": fname, "url": furl, "size": f.get("size"), "hash": f.get("hash")})
            except Exception:
                pass

            chall = Challenge(
                id=cid,
                name=title,
                category=main_cat,
                points=item.get("value", 0),
                description=description,
                author=tags_dict.get("author"),
                tags=[tags_dict.get("difficulty", "")] if tags_dict.get("difficulty") else [],
                hints=[],
                files=files_list,
                connection_info=None,
                solved_by_me=item.get("solved_by_me", False),
                solves_count=item.get("solve_count", 0),
                is_dynamic_container=False,
                raw_data=item
            )
            challenges.append(chall)

        return challenges

    def submit_flag(self, challenge_id: Any, flag: str) -> SubmitResult:
        payload = {"data": flag.strip()}
        try:
            resp = self.client.post(f"/challenges/{challenge_id}/solves", json=payload)
            if resp.status_code == 429:
                return SubmitResult(
                    verdict="ratelimited",
                    message="Bị giới hạn tốc độ (Rate Limited). Vui lòng thử lại sau.",
                    challenge_id=challenge_id,
                    flag=flag
                )
            if resp.status_code in [401, 403]:
                return SubmitResult(
                    verdict="auth_failed",
                    message="Token xác thực không hợp lệ hoặc đã hết hạn.",
                    challenge_id=challenge_id,
                    flag=flag
                )

            body = resp.json() if resp.text else {}
            data = body.get("data", {})
            status = data.get("status", "")

            if status == "correct":
                return SubmitResult(
                    verdict="correct",
                    message="Flag chính xác! Điểm đã được cộng thành công.",
                    challenge_id=challenge_id,
                    flag=flag
                )
            elif status == "already_solved":
                return SubmitResult(
                    verdict="already_solved",
                    message="Bài này bạn hoặc team đã giải trước đó rồi.",
                    challenge_id=challenge_id,
                    flag=flag
                )
            elif status == "incorrect":
                return SubmitResult(
                    verdict="incorrect",
                    message="Flag không chính xác.",
                    challenge_id=challenge_id,
                    flag=flag
                )
            else:
                return SubmitResult(
                    verdict="error",
                    message=f"Status: {status} - {body}",
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
