import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional
import httpx
from rich.console import Console

console = Console()

class DownloadManager:
    def __init__(
        self,
        session_cookie: Optional[str] = None,
        api_token: Optional[str] = None,
        max_workers: int = 5,
        timeout: int = 30
    ):
        self.session_cookie = session_cookie
        self.api_token = api_token
        self.max_workers = max_workers
        self.timeout = timeout
        
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
        }
        if self.session_cookie:
            headers["Cookie"] = self.session_cookie
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"
            
        self.client = httpx.Client(headers=headers, timeout=self.timeout, follow_redirects=True)

    def close(self):
        self.client.close()

    def _sanitize_filename(self, filename: Optional[str], fallback: str = "attachment") -> str:
        if not filename:
            return fallback
        # Lấy tên file gốc, loại bỏ đường dẫn tương đối hoặc tuyệt đối
        name = Path(filename).name.strip()
        # Loại bỏ các ký tự điều khiển nguy hiểm
        name = re.sub(r'[\x00-\x1f\x7f]', '', name)
        # Loại bỏ các chuỗi traversal còn sót
        name = name.replace("..", "").strip()
        return name or fallback

    def download_file(self, url: str, target_dir: Path, suggested_name: Optional[str] = None) -> Optional[Path]:
        """Tải một file đính kèm về target_dir (có kiểm tra an toàn path traversal và cache)."""
        target_dir = Path(target_dir).resolve()
        target_dir.mkdir(parents=True, exist_ok=True)

        raw_filename = suggested_name or os.path.basename(url.split("?")[0])
        safe_filename = self._sanitize_filename(raw_filename)
        dest_file = (target_dir / safe_filename).resolve()

        # Kiểm tra van an toàn: không cho phép ghi ngoài target_dir
        if not dest_file.is_relative_to(target_dir):
            console.print(f"[bold red]❌ Phát hiện Path Traversal nguy hiểm từ URL {url}: '{raw_filename}'[/bold red]")
            return None

        if dest_file.is_file() and dest_file.stat().st_size > 0:
            console.print(f"[dim]⚡ Tệp đã tồn tại trong cache: {dest_file.name}[/dim]")
            return dest_file
        
        # 1. Xử lý Google Drive URL
        if "drive.google.com" in url:
            file_id_match = re.search(r'/d/([a-zA-Z0-9_-]+)', url) or re.search(r'id=([a-zA-Z0-9_-]+)', url)
            if file_id_match:
                file_id = file_id_match.group(1)
                url = f"https://drive.google.com/uc?export=download&id={file_id}"

        # 2. Thực hiện tải qua httpx stream
        try:
            with self.client.stream("GET", url) as resp:
                if resp.status_code != 200:
                    console.print(f"[yellow]⚠️ Tải file thất bại ({resp.status_code}): {url}[/yellow]")
                    return None
                
                cd = resp.headers.get("Content-Disposition", "")
                if "filename=" in cd and not suggested_name:
                    matches = re.findall(r'filename=["\']?([^"\';]+)["\']?', cd)
                    if matches:
                        safe_cd_name = self._sanitize_filename(matches[0])
                        dest_file = (target_dir / safe_cd_name).resolve()
                        if not dest_file.is_relative_to(target_dir):
                            console.print(f"[bold red]❌ Phát hiện Path Traversal trong Content-Disposition: '{matches[0]}'[/bold red]")
                            return None
                        if dest_file.is_file() and dest_file.stat().st_size > 0:
                            return dest_file
                
                with open(dest_file, "wb") as f:
                    for chunk in resp.iter_bytes(chunk_size=8192):
                        f.write(chunk)
                return dest_file
        except Exception as e:
            console.print(f"[red]❌ Lỗi tải tệp {url}: {e}[/red]")
            return None

    def download_attachments(
        self,
        files: List[Dict[str, str]],
        target_dir: Path
    ) -> List[Path]:
        """Tải song song danh sách attachments bằng ThreadPoolExecutor."""
        if not files:
            return []
            
        downloaded: List[Path] = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(
                    self.download_file,
                    item.get("url", ""),
                    target_dir,
                    item.get("name")
                ): item for item in files if item.get("url")
            }
            for future in as_completed(futures):
                res = future.result()
                if res:
                    downloaded.append(res)
        return downloaded
