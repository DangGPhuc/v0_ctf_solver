import base64
import json
import os
import re
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import httpx
from rich.console import Console

from ..models import CTFInfo, Challenge, ContainerInfo, SubmitResult, SubmitVerdict
from ..config import load_config, save_env_file, find_env_file
from .base import BasePlatform
from .registry import register_platform

console = Console()

SUPABASE_URL = "https://ikdyrqwdltinghuecvsb.supabase.co"
SUPABASE_ANON_KEY = "sb_publishable_f943vmSm6awO2U4o9y_O9g_XJhtpQVK"

def get_tokens_from_firefox() -> Tuple[Optional[str], Optional[str], Optional[float]]:
    """
    Tự động trích xuất Supabase Auth Tokens (access_token, refresh_token, expires_at)
    từ Firefox LocalStorage (SQLite snappy compressed).
    """
    try:
        import sqlite3
        import cramjam
        
        ff_dir = Path.home() / ".mozilla" / "firefox"
        if not ff_dir.exists():
            return None, None, None
            
        for profile in ff_dir.iterdir():
            if not profile.is_dir():
                continue
            ls_db = profile / "storage" / "default" / "https+++ctf.cyberhx.com" / "ls" / "data.sqlite"
            if ls_db.is_file():
                conn = sqlite3.connect(f"file:{ls_db}?immutable=1", uri=True)
                cur = conn.cursor()
                cur.execute('SELECT value FROM data WHERE key LIKE "%auth-token%"')
                row = cur.fetchone()
                conn.close()
                if row and row[0]:
                    raw_val = row[0]
                    try:
                        decomp = bytes(cramjam.snappy.decompress_raw(raw_val))
                        parsed = json.loads(decomp.decode("utf-8"))
                        return (
                            parsed.get("access_token"),
                            parsed.get("refresh_token"),
                            parsed.get("expires_at")
                        )
                    except Exception:
                        pass
    except Exception:
        pass
    return None, None, None

def get_token_from_firefox() -> Optional[str]:
    """Hàm tương thích ngược trả về access_token."""
    at, _, _ = get_tokens_from_firefox()
    return at


@register_platform(
    name="cyberhx",
    markers=["cyberhx", "Null Origin", "ikdyrqwdltinghuecvsb", "nullorigin"],
    cookie_hints=["cf_clearance", "cyberhx"]
)
class CyberHXPlatform(BasePlatform):
    """
    Platform Adapter cho CyberHX CTF / Null Origin CTF (nền tảng Next.js/Vercel + Supabase).
    Tích hợp Supabase Auth Token Lifecycle Engine:
    - Tự động làm mới access_token trước khi hết hạn (exp - 300s) qua refresh_token.
    - Fallback tự động làm mới khi gặp HTTP 401 và retry request 1 lần.
    - Quản lý session HTTP persistent kèm cookie và chuẩn header Firefox 140.
    - Rate-limiting an toàn tránh bị WAF / Cloudflare chặn IP.
    """
    def __init__(
        self,
        url: str = "https://ctf.cyberhx.com",
        session_cookie: Optional[str] = None,
        api_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
        token_expires_at: Optional[float] = None,
        timeout: int = 30,
        **kwargs
    ):
        super().__init__(url=url, session_cookie=session_cookie, api_token=api_token, timeout=timeout)
        self.supabase_url = SUPABASE_URL
        self.anon_key = SUPABASE_ANON_KEY
        
        cfg = load_config()
        self.refresh_token = refresh_token or cfg.refresh_token or os.environ.get("REFRESH_TOKEN")
        self.token_expires_at = token_expires_at or cfg.token_expires_at

        # Nếu thiếu token, tự động đọc từ Firefox LocalStorage
        if not self.api_token or not self.refresh_token:
            ff_at, ff_rt, ff_exp = get_tokens_from_firefox()
            if not self.api_token and ff_at:
                self.api_token = ff_at
            if not self.refresh_token and ff_rt:
                self.refresh_token = ff_rt
            if not self.token_expires_at and ff_exp:
                self.token_expires_at = ff_exp

        # Nếu có api_token nhưng chưa có token_expires_at, giải mã từ JWT exp
        if self.api_token and not self.token_expires_at:
            self.token_expires_at = self._decode_jwt_exp(self.api_token)

        self._user_email: Optional[str] = None
        self._user_id: Optional[str] = None
        self._solves_set: set = set()
        
        # Rate-limiting state
        self._last_request_time: float = 0.0
        self._min_interval: float = 0.35  # Tối thiểu 350ms giữa các request

        # Khởi tạo persistent client
        self.client = httpx.Client(
            headers=self._get_base_headers(),
            timeout=self.timeout,
            follow_redirects=True
        )

    def _decode_jwt_exp(self, token: str) -> Optional[float]:
        """Giải mã timestamp hết hạn (exp) từ JWT payload."""
        try:
            parts = token.split(".")
            if len(parts) >= 2:
                payload_b64 = parts[1]
                payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
                data = json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))
                return float(data.get("exp", 0))
        except Exception:
            pass
        return None

    def _get_base_headers(self) -> Dict[str, str]:
        headers = {
            "apikey": self.anon_key,
            "Content-Type": "application/json",
            "Origin": "https://ctf.cyberhx.com",
            "Referer": "https://ctf.cyberhx.com/",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
            "Accept": "*/*",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "cross-site",
        }
        if self.session_cookie:
            headers["Cookie"] = self.session_cookie
        return headers

    def _get_headers(self) -> Dict[str, str]:
        headers = self._get_base_headers()
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"
        return headers

    def refresh_supabase_token(self, force: bool = False) -> bool:
        """
        Làm mới access_token bằng refresh_token qua endpoint Supabase Auth.
        Được kích hoạt chủ động nếu time.time() >= exp - 300s (còn dưới 5 phút)
        hoặc khi force=True (gặp lỗi 401).
        """
        if not self.refresh_token:
            # Thử kéo lại từ Firefox LocalStorage lần nữa
            _, ff_rt, _ = get_tokens_from_firefox()
            if ff_rt:
                self.refresh_token = ff_rt
            else:
                return False

        now = time.time()
        # Nếu chưa hết hạn và không bị force, bỏ qua
        if not force and self.token_expires_at and now < (self.token_expires_at - 300):
            return True

        refresh_url = f"{self.supabase_url}/auth/v1/token?grant_type=refresh_token"
        headers = self._get_base_headers()
        payload = {"refresh_token": self.refresh_token}

        console.print("[cyan]🔄 Đang tự động làm mới Supabase Auth Token qua Refresh Token...[/cyan]")
        try:
            resp = httpx.post(refresh_url, headers=headers, json=payload, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                new_access_token = data.get("access_token")
                new_refresh_token = data.get("refresh_token")
                new_expires_at = data.get("expires_at")
                if not new_expires_at and "expires_in" in data:
                    new_expires_at = time.time() + float(data["expires_in"])

                if new_access_token:
                    self.api_token = new_access_token
                    if new_refresh_token:
                        self.refresh_token = new_refresh_token
                    if new_expires_at:
                        self.token_expires_at = float(new_expires_at)

                    # Đồng bộ lưu lại vào tệp .env duy nhất (phân quyền bảo mật 0600)
                    tokens_dict = {
                        "API_TOKEN": self.api_token,
                        "REFRESH_TOKEN": self.refresh_token,
                        "TOKEN_EXPIRES_AT": self.token_expires_at
                    }
                    canonical_env = find_env_file() or (Path.cwd() / ".env")
                    try:
                        save_env_file(canonical_env, tokens_dict)
                    except Exception:
                        pass
                    console.print("[bold green]✔ Đã làm mới token thành công! Phiên giải đấu được duy trì an toàn.[/bold green]")
                    return True
                else:
                    console.print(f"[yellow]⚠️ Phản hồi làm mới thiếu access_token: {data}[/yellow]")
            else:
                console.print(f"[yellow]⚠️ Không thể làm mới token (HTTP {resp.status_code}): {resp.text[:150]}[/yellow]")
        except Exception as e:
            console.print(f"[red]❌ Lỗi mạng khi làm mới token: {e}[/red]")

        return False

    def _request(self, method: str, url: str, retry_auth: bool = True, **kwargs) -> httpx.Response:
        """
        Wrapper gửi request tích hợp:
        - Rate limiting & delay an toàn
        - Tự động kiểm tra hạn token trước khi gọi
        - Fallback làm mới token khi gặp 401 Unauthorized
        """
        # 1. Rate Limiting: đảm bảo giãn cách tối thiểu giữa các request
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request_time = time.time()

        # 2. Kiểm tra và chủ động làm mới token nếu sắp hết hạn (< 5 phút)
        self.refresh_supabase_token(force=False)

        # 3. Chuẩn bị headers kèm token mới nhất
        headers = kwargs.pop("headers", None) or self._get_headers()

        resp = self.client.request(method, url, headers=headers, **kwargs)

        # 4. Fallback khi gặp 401 Unauthorized: Refresh token và thử lại 1 lần
        if resp.status_code == 401 and retry_auth:
            console.print("[yellow]⚠️ Gặp lỗi 401 Unauthorized — Đang kích hoạt làm mới token tức thì...[/yellow]")
            if self.refresh_supabase_token(force=True):
                # Cập nhật Authorization header mới và retry
                retry_headers = self._get_headers()
                resp = self.client.request(method, url, headers=retry_headers, **kwargs)

        # 5. Xử lý Rate Limited (429)
        if resp.status_code == 429:
            retry_after = resp.headers.get("Retry-After")
            wait_s = float(retry_after) if retry_after and retry_after.isdigit() else 3.0
            console.print(f"[yellow]⏳ Gặp HTTP 429 (Rate Limit), tạm dừng {wait_s}s...[/yellow]")
            time.sleep(wait_s)

        return resp

    def authenticate(self) -> bool:
        """Kiểm tra token bằng cách gọi Supabase REST API."""
        if not self.api_token:
            self.refresh_supabase_token(force=True)
        if not self.api_token:
            return False

        try:
            resp = self._request(
                "GET",
                f"{self.supabase_url}/rest/v1/public_challenges?select=id&limit=1"
            )
            if resp.status_code == 200:
                try:
                    payload_b64 = self.api_token.split(".")[1]
                    payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
                    payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode())
                    self._user_email = payload.get("email")
                    self._user_id = payload.get("sub")
                except Exception:
                    pass
                return True
        except Exception:
            pass
        return False

    def fetch_ctf_info(self) -> CTFInfo:
        return CTFInfo(
            title="Null Origin CTF 2026 (CyberHX)",
            platform="cyberhx",
            url=self.url or "https://ctf.cyberhx.com",
            user_name=self._user_email or "CyberHX Contestant",
            team_name=self._user_email or "CyberHX Team",
            flag_format=r"^Null0rigin\{.+\}$"
        )

    def fetch_challenges(self, category: Optional[str] = None) -> List[Challenge]:
        challenges: List[Challenge] = []

        # 1. Lấy danh sách bài đã giải của thí sinh
        try:
            sub_resp = self._request(
                "GET",
                f"{self.supabase_url}/rest/v1/submissions?select=challenge_id&is_correct=eq.true"
            )
            if sub_resp.status_code == 200:
                self._solves_set = {s["challenge_id"] for s in sub_resp.json() if "challenge_id" in s}
        except Exception:
            pass

        # 2. Truy vấn toàn bộ public_challenges kèm files và hints
        select_query = (
            "id,title,category,difficulty,points,description,author,is_visible,"
            "tags,created_at,max_attempts,connection_info,"
            "files:challenge_files(id,name,url,size_bytes),hints(id,cost)"
        )
        try:
            resp = self._request(
                "GET",
                f"{self.supabase_url}/rest/v1/public_challenges",
                params={"select": select_query, "is_visible": "eq.true"}
            )
            if resp.status_code != 200:
                return challenges
            items = resp.json()
        except Exception:
            return challenges

        # Bản đồ chuẩn hóa category
        cat_map = {
            "rev": "Rev",
            "reverse": "Rev",
            "reversing": "Rev",
            "web": "Web",
            "pwn": "Pwn",
            "forensic": "Forensics",
            "forensics": "Forensics",
            "crypto": "Crypto",
            "osint": "Misc",
            "misc": "Misc"
        }

        norm_filter = category.strip().lower() if category else None
        if norm_filter and norm_filter in cat_map:
            norm_filter = cat_map[norm_filter].lower()

        for item in items:
            cid = str(item.get("id"))
            cname = item.get("title", f"chall_{cid}")
            raw_cat = item.get("category", "Misc").capitalize()
            cat_normalized = cat_map.get(raw_cat.lower(), raw_cat)

            # Lọc theo danh mục nếu được chỉ định (cho thi đấu phân chia VM)
            if norm_filter and cat_normalized.lower() != norm_filter:
                continue

            # Bóc tách files từ challenge_files
            files_list = []
            for f in item.get("files", []):
                fname = f.get("name")
                furl = f.get("url", "")
                if furl:
                    if not fname:
                        fname = os.path.basename(furl.split("?")[0]) or "attachment"
                    files_list.append({"name": fname, "url": furl})

            # Bóc tách files từ connection_info (nếu có github releases / cdn link)
            conn_info_raw = item.get("connection_info")
            conn_str = ""
            if conn_info_raw:
                try:
                    if isinstance(conn_info_raw, str) and (conn_info_raw.startswith("[") or conn_info_raw.startswith("{")):
                        conn_parsed = json.loads(conn_info_raw)
                    else:
                        conn_parsed = conn_info_raw
                    
                    if isinstance(conn_parsed, list):
                        for entry in conn_parsed:
                            if isinstance(entry, dict):
                                e_url = entry.get("url", "")
                                e_label = entry.get("label", "")
                                if any(ext in e_url.lower() for ext in [".7z", ".zip", ".tar", ".gz", "/releases/download/", "/ctf_attachements/"]):
                                    f_name = e_label or os.path.basename(e_url.split("?")[0])
                                    if not any(fl["url"] == e_url for fl in files_list):
                                        files_list.append({"name": f_name, "url": e_url})
                                else:
                                    conn_str += f"{e_label}: {e_url}\n"
                    elif isinstance(conn_parsed, dict):
                        conn_str = json.dumps(conn_parsed)
                    else:
                        conn_str = str(conn_parsed)
                except Exception:
                    conn_str = str(conn_info_raw)

            hints_list = []
            for h in item.get("hints", []):
                hints_list.append(h)

            chall = Challenge(
                id=cid,
                name=cname,
                category=cat_normalized,
                points=item.get("points", 0),
                description=item.get("description", "") or "",
                author=item.get("author"),
                tags=item.get("tags") or [],
                hints=hints_list,
                files=files_list,
                connection_info=conn_str.strip() or None,
                solved_by_me=(cid in self._solves_set),
                solves_count=None,
                is_dynamic_container=False,
                raw_data=item
            )
            challenges.append(chall)

        return challenges

    def submit_flag(self, challenge_id: Any, flag: str) -> SubmitResult:
        """Nộp flag qua Edge Function submit-flag của Supabase."""
        url = f"{self.supabase_url}/functions/v1/submit-flag"
        payload = {
            "challengeId": str(challenge_id),
            "flag": flag.strip()
        }

        try:
            resp = self._request("POST", url, json=payload)
            
            if resp.status_code == 429:
                return SubmitResult(
                    verdict="ratelimited",
                    message="Bị giới hạn tốc độ nộp flag (Rate Limited). Vui lòng thử lại sau giây lát.",
                    challenge_id=challenge_id,
                    flag=flag
                )
            if resp.status_code in [401, 403]:
                return SubmitResult(
                    verdict="auth_failed",
                    message="Phiên đăng nhập hết hạn hoặc chưa xác thực (401/403).",
                    challenge_id=challenge_id,
                    flag=flag
                )

            body = resp.json() if resp.text else {}
            
            if body.get("correct") is True:
                if body.get("alreadySolved") is True:
                    return SubmitResult(
                        verdict="already_solved",
                        message="Challenge này đã được giải trước đó trên hệ thống!",
                        challenge_id=challenge_id,
                        flag=flag,
                        points=body.get("points")
                    )
                return SubmitResult(
                    verdict="correct",
                    message=body.get("message", "Flag chính xác! Điểm đã được ghi nhận."),
                    challenge_id=challenge_id,
                    flag=flag,
                    points=body.get("points")
                )
            else:
                msg = body.get("message", "Access Denied: Invalid Key Sequence")
                if body.get("eventEnded"):
                    msg = "Sự kiện đã kết thúc — không nhận cờ nữa."
                return SubmitResult(
                    verdict="incorrect",
                    message=msg,
                    challenge_id=challenge_id,
                    flag=flag
                )

        except Exception as e:
            return SubmitResult(
                verdict="error",
                message=f"Lỗi kết nối khi nộp cờ: {e}",
                challenge_id=challenge_id,
                flag=flag
            )
