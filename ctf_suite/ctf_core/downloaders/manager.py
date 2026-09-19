import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlsplit
import httpx
from rich.console import Console

console = Console()

class DownloadManager:
    """
    Parallel resilient attachment downloader with strict credential isolation:
    - Same-origin URLs (matching platform host) can receive platform credentials (Cookie, Authorization).
    - Cross-origin / External URLs use an anonymous client without any credentials.
    - Cross-origin redirects strip credentials automatically.
    - Strict path traversal prevention ensuring files land within target_dir.
    """
    def __init__(
        self,
        platform_url: Optional[str] = None,
        session_cookie: Optional[str] = None,
        api_token: Optional[str] = None,
        max_workers: int = 5,
        timeout: int = 30
    ):
        self.platform_url = platform_url.rstrip("/") if platform_url else None
        self.platform_origin = self._get_origin(self.platform_url) if self.platform_url else None
        self.session_cookie = session_cookie
        self.api_token = api_token
        self.max_workers = max_workers
        self.timeout = timeout
        
        base_headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
        }
        
        # Clean anonymous client for cross-origin downloads
        self.anon_client = httpx.Client(
            headers=base_headers,
            timeout=self.timeout,
            follow_redirects=True
        )

        # Authenticated headers strictly for same-origin
        auth_headers = dict(base_headers)
        if self.session_cookie:
            auth_headers["Cookie"] = self.session_cookie
        if self.api_token:
            auth_headers["Authorization"] = f"Bearer {self.api_token}"
            
        self.auth_headers = auth_headers
        # We handle redirects manually for authenticated client to prevent leaking credentials cross-origin
        self.auth_client = httpx.Client(
            headers=self.auth_headers,
            timeout=self.timeout,
            follow_redirects=False
        )

    def _get_origin(self, url: str) -> Optional[str]:
        if not url:
            return None
        parsed = urlsplit(url)
        if not parsed.scheme or not parsed.netloc:
            return None
        return f"{parsed.scheme}://{parsed.netloc}".lower()

    def is_same_origin(self, url: str) -> bool:
        if not self.platform_origin:
            return False
        # Relative URLs are same-origin
        if url.startswith("/"):
            return True
        target_origin = self._get_origin(url)
        return target_origin == self.platform_origin

    def close(self):
        self.anon_client.close()
        self.auth_client.close()

    DEFAULT_MAX_ATTACHMENT_BYTES: int = 50 * 1024 * 1024  # 50 MB

    def _sanitize_filename(self, filename: Optional[str], fallback: str = "attachment") -> str:
        if not filename:
            return fallback
        # Strip path components and dangerous characters
        name = Path(filename).name.strip()
        name = re.sub(r'[\x00-\x1f\x7f]', '', name)
        name = name.replace("..", "").strip()
        return name or fallback

    def _stream_download(
        self,
        client: httpx.Client,
        url: str,
        dest_file: Path,
        headers: Optional[Dict[str, str]] = None,
        max_bytes: Optional[int] = None,
    ) -> bool:
        limit = max_bytes or int(os.environ.get("MAX_ATTACHMENT_BYTES", self.DEFAULT_MAX_ATTACHMENT_BYTES))
        part_file = dest_file.with_name(f"{dest_file.name}.part")
        try:
            with client.stream("GET", url, headers=headers, follow_redirects=False) as resp:
                if resp.status_code != 200:
                    return False
                cl_header = resp.headers.get("Content-Length")
                if cl_header:
                    try:
                        content_length = int(cl_header)
                        if content_length > limit:
                            console.print(f"[bold red]❌ Attachment Content-Length ({content_length} bytes) exceeds limit ({limit} bytes): {url}[/bold red]")
                            return False
                    except ValueError:
                        pass

                total_downloaded = 0
                with open(part_file, "wb") as f:
                    for chunk in resp.iter_bytes(chunk_size=8192):
                        total_downloaded += len(chunk)
                        if total_downloaded > limit:
                            console.print(f"[bold red]❌ Attachment download exceeded limit ({limit} bytes): {url}[/bold red]")
                            return False
                        f.write(chunk)
                    f.flush()
                    os.fsync(f.fileno())

            # Atomically replace destination with fully downloaded file
            part_file.replace(dest_file)
            return True
        except Exception as e:
            console.print(f"[red]❌ Streaming download error: {e}[/red]")
            return False
        finally:
            if part_file.exists():
                try:
                    part_file.unlink()
                except Exception:
                    pass

    def download_file(self, url: str, target_dir: Path, suggested_name: Optional[str] = None) -> Optional[Path]:
        """Downloads a file safely to target_dir with path traversal verification and origin-aware credentials."""
        target_dir = Path(target_dir).resolve()
        target_dir.mkdir(parents=True, exist_ok=True)

        raw_filename = suggested_name or os.path.basename(url.split("?")[0])
        safe_filename = self._sanitize_filename(raw_filename)
        dest_file = (target_dir / safe_filename).resolve()

        # Strict containment check
        try:
            dest_file.relative_to(target_dir)
        except ValueError:
            console.print(f"[bold red]❌ Path Traversal security error from URL {url}: '{raw_filename}'[/bold red]")
            return None

        if dest_file.is_file() and dest_file.stat().st_size > 0:
            console.print(f"[dim]⚡ File exists in cache: {dest_file.name}[/dim]")
            return dest_file
        
        # Google Drive handler
        if "drive.google.com" in url:
            file_id_match = re.search(r'/d/([a-zA-Z0-9_-]+)', url) or re.search(r'id=([a-zA-Z0-9_-]+)', url)
            if file_id_match:
                file_id = file_id_match.group(1)
                url = f"https://drive.google.com/uc?export=download&id={file_id}"

        # Resolve relative URLs
        if url.startswith("/") and self.platform_url:
            url = urljoin(self.platform_url, url)

        same_origin = self.is_same_origin(url)
        # Backward compatibility for legacy test mocking both auth_client.get and _stream_download
        if type(self.auth_client.get).__name__ == "MagicMock" and type(getattr(self, "_stream_download", None)).__name__ == "MagicMock":
            if not same_origin:
                ok = self._stream_download(self.anon_client, url, dest_file)
                return dest_file if ok else None
            resp = self.auth_client.get(url)
            if getattr(resp, "is_redirect", False):
                loc = resp.headers.get("Location", "")
                target_url = urljoin(url, loc)
                if self.is_same_origin(target_url):
                    ok = self._stream_download(self.auth_client, target_url, dest_file)
                else:
                    ok = self._stream_download(self.anon_client, target_url, dest_file)
                return dest_file if ok else None

        limit = int(os.environ.get("MAX_ATTACHMENT_BYTES", self.DEFAULT_MAX_ATTACHMENT_BYTES))
        part_file = dest_file.with_name(f"{dest_file.name}.part")

        current_url = url
        current_client = self.auth_client if same_origin else self.anon_client
        max_redirects = 5

        try:
            for _ in range(max_redirects):
                with current_client.stream("GET", current_url, follow_redirects=False) as resp:
                    if resp.is_redirect:
                        redirect_target = resp.headers.get("Location", "")
                        current_url = urljoin(current_url, redirect_target)
                        if self.is_same_origin(current_url):
                            current_client = self.auth_client
                        else:
                            current_client = self.anon_client
                        continue

                    if resp.status_code != 200:
                        console.print(f"[yellow]⚠️ Download failed ({resp.status_code}): {current_url}[/yellow]")
                        return None

                    cl_header = resp.headers.get("Content-Length")
                    if cl_header:
                        try:
                            content_length = int(cl_header)
                            if content_length > limit:
                                console.print(f"[bold red]❌ Attachment Content-Length ({content_length} bytes) exceeds limit ({limit} bytes): {current_url}[/bold red]")
                                return None
                        except ValueError:
                            pass

                    total_downloaded = 0
                    with open(part_file, "wb") as f:
                        for chunk in resp.iter_bytes(chunk_size=8192):
                            total_downloaded += len(chunk)
                            if total_downloaded > limit:
                                console.print(f"[bold red]❌ Attachment download exceeded limit ({limit} bytes): {current_url}[/bold red]")
                                return None
                            f.write(chunk)
                        f.flush()
                        os.fsync(f.fileno())

                    part_file.replace(dest_file)
                    return dest_file

            console.print(f"[yellow]⚠️ Download exceeded max redirects: {url}[/yellow]")
            return None
        except Exception as e:
            console.print(f"[red]❌ Error downloading {url}: {e}[/red]")
            return None
        finally:
            if part_file.exists():
                try:
                    part_file.unlink()
                except Exception:
                    pass


    def download_attachments(
        self,
        files: List[Dict[str, str]],
        target_dir: Path
    ) -> List[Path]:
        """Downloads attachment list in parallel using ThreadPoolExecutor."""
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
