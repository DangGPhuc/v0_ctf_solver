import json
import os
import shutil
import subprocess
import httpx
import yaml
from typing import Any, Dict, List, Optional
from rich.console import Console

from .cache import KnowledgeCache
from .models import KnowledgeDocument, KnowledgeHit, KnowledgeQuery
from .provider import score_entry

console = Console()

class GitHubKnowledgeProvider:
    """
    On-demand 'Drive mode' knowledge provider accessing GitHub repository
    via official GitHub REST Contents API.
    Does NOT clone repository. Fetches and caches index and individual documents.
    Supports private repositories via authenticated raw+json contents requests.
    """

    def __init__(
        self,
        repo: str = "DangGPhuc/v0_ctf_knowledge",
        ref: str = "main",
        cache: Optional[KnowledgeCache] = None,
        offline: bool = False,
        ttl_seconds: int = 900,
        token: Optional[str] = None,
    ):
        self.repo = repo
        self.ref = ref
        self.cache = cache or KnowledgeCache(default_ttl_seconds=ttl_seconds)
        self.offline = offline
        self.ttl_seconds = ttl_seconds
        self.token = token if token is not None else self._resolve_token()
        self._index_entries: List[Dict[str, Any]] = []
        self._load_or_sync_index()

    def _resolve_token(self) -> Optional[str]:
        # 1. Environment variables
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if token and token.strip():
            return token.strip()
        # 2. gh CLI auth token
        if shutil.which("gh"):
            try:
                res = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=3)
                if res.returncode == 0 and res.stdout.strip():
                    return res.stdout.strip()
            except Exception:
                pass
        return None

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "User-Agent": "v0-ctf-solver/2.0",
            "Accept": "application/vnd.github.raw+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _load_or_sync_index(self):
        # 1. Check local cache freshness
        is_fresh = self.cache.is_index_fresh(self.repo, self.ref, self.ttl_seconds)
        cached = self.cache.get_cached_index(self.repo, self.ref)

        if is_fresh and cached:
            self._index_entries = cached
            return

        if self.offline:
            if cached:
                console.print("[yellow]⚠️ Running offline: using cached knowledge index.[/yellow]")
                self._index_entries = cached
            return

        # 2. Stale or missing: attempt remote sync
        synced = self.sync_index()
        if not synced and cached:
            # Graceful degradation: stale cache fallback
            console.print("[yellow]⚠️ Remote sync failed; degrading gracefully to stale cache.[/yellow]")
            self._index_entries = cached

    def sync_index(self, force: bool = False) -> bool:
        """Download latest index.jsonl from GitHub REST Contents API and update local cache."""
        if self.offline:
            console.print("[yellow]⚠️ Running in offline mode; skipping remote knowledge sync.[/yellow]")
            return False

        url = f"https://api.github.com/repos/{self.repo}/contents/index.jsonl?ref={self.ref}"
        console.print(f"[dim]🌐 Fetching knowledge index from {self.repo}:{self.ref} via GitHub Contents API...[/dim]")

        try:
            with httpx.Client(timeout=10.0, headers=self._get_headers(), follow_redirects=True) as client:
                res = client.get(url)
                if res.status_code == 200:
                    entries = []
                    for line in res.text.splitlines():
                        line = line.strip()
                        if line:
                            entries.append(json.loads(line))
                    self._index_entries = entries
                    self.cache.store_index(self.repo, self.ref, entries, ttl_seconds=self.ttl_seconds)
                    console.print(f"[bold green]✔ Successfully synced {len(entries)} knowledge index entries![/bold green]")
                    return True
                elif res.status_code in [403, 404]:
                    console.print(f"[yellow]⚠️ GitHub API returned {res.status_code} for {self.repo}:{self.ref} (authentication or repo existence issue). Solver will continue gracefully.[/yellow]")
                else:
                    console.print(f"[yellow]⚠️ Failed to fetch index ({res.status_code}): {res.text[:100]}. Solver will continue gracefully.[/yellow]")
        except Exception as e:
            console.print(f"[yellow]⚠️ Remote knowledge provider unavailable ({e}). Continuing with cached or local knowledge.[/yellow]")

        return False

    def search(self, query: KnowledgeQuery, limit: int = 5) -> List[KnowledgeHit]:
        scored_hits: List[KnowledgeHit] = []
        for entry in self._index_entries:
            score, matched_on = score_entry(entry, query)
            if score > 0:
                hit = KnowledgeHit(
                    id=entry.get("id", ""),
                    score=score,
                    matched_on=matched_on,
                    path=entry.get("path", ""),
                    kind=entry.get("kind", "technique"),
                    status=entry.get("status", "active"),
                    blob_sha=entry.get("blob_sha", ""),
                    title=entry.get("title", ""),
                    summary=entry.get("summary", ""),
                )
                scored_hits.append(hit)

        scored_hits.sort(key=lambda h: h.score, reverse=True)
        return scored_hits[:limit]

    def fetch(self, hit_or_id: Any) -> Optional[KnowledgeDocument]:
        rel_path = None
        cid = None
        blob_sha = ""

        if isinstance(hit_or_id, KnowledgeHit):
            rel_path = hit_or_id.path
            cid = hit_or_id.id
            blob_sha = hit_or_id.blob_sha
        elif isinstance(hit_or_id, str):
            cid = hit_or_id
            for ent in self._index_entries:
                if ent.get("id") == cid:
                    rel_path = ent.get("path")
                    blob_sha = ent.get("blob_sha", "")
                    break

        if not rel_path:
            return None

        # 1. Check local object cache
        key = blob_sha or rel_path
        cached_content = self.cache.get_object(key, repo=self.repo if not blob_sha else None)
        if not cached_content and rel_path:
            cached_content = self.cache.get_object(rel_path, repo=self.repo)

        if cached_content:
            return self._parse_document(cached_content, cid or "", blob_sha)

        if self.offline:
            return None

        # 2. Fetch on-demand from remote GitHub REST Contents API
        clean_path = rel_path.lstrip("/")
        url = f"https://api.github.com/repos/{self.repo}/contents/{clean_path}?ref={self.ref}"
        try:
            with httpx.Client(timeout=10.0, headers=self._get_headers(), follow_redirects=True) as client:
                res = client.get(url)
                if res.status_code == 200:
                    content = res.text
                    if blob_sha:
                        self.cache.store_object(blob_sha, content)
                    self.cache.store_object(rel_path, content, repo=self.repo)
                    return self._parse_document(content, cid or "", blob_sha)
                else:
                    console.print(f"[yellow]⚠️ GitHub API returned {res.status_code} fetching {rel_path}[/yellow]")
        except Exception as e:
            console.print(f"[yellow]⚠️ Failed to fetch knowledge card {cid}: {e}[/yellow]")

        return None

    def _parse_document(self, content: str, cid: str, blob_sha: str) -> Optional[KnowledgeDocument]:
        try:
            data = yaml.safe_load(content)
            if not isinstance(data, dict):
                return None
            tech = data.get("technique", {})
            steps = tech.get("steps", []) if isinstance(tech, dict) else []

            return KnowledgeDocument(
                id=data.get("id", cid),
                title=data.get("title", ""),
                category=data.get("category", ""),
                tags=data.get("tags", []),
                status=data.get("status", "active"),
                summary=data.get("summary", ""),
                signals=data.get("signals", []),
                technique_steps=steps,
                verification=data.get("verification", []),
                failure_modes=data.get("failure_modes", []),
                tool_hints=data.get("tool_hints", []),
                content_raw=content,
                blob_sha=blob_sha,
            )
        except Exception:
            return None

    def check_doctor(self) -> Dict[str, Any]:
        """Diagnostic probe for doctor command. Never exposes tokens."""
        meta = self.cache.get_index_metadata(self.repo, self.ref)
        is_fresh = self.cache.is_index_fresh(self.repo, self.ref, self.ttl_seconds)
        cache_status = "fresh" if is_fresh else ("stale" if meta else "empty")
        last_sync = meta.get("cached_at", "never") if meta else "never"

        remote_reachable = False
        if not self.offline:
            try:
                url = f"https://api.github.com/repos/{self.repo}"
                with httpx.Client(timeout=5.0, headers=self._get_headers()) as client:
                    res = client.get(url)
                    remote_reachable = (res.status_code in [200, 301, 302])
            except Exception:
                remote_reachable = False

        return {
            "provider": "github",
            "repo": self.repo,
            "ref": self.ref,
            "authenticated": bool(self.token),
            "remote_reachable": remote_reachable,
            "cache_status": cache_status,
            "index_entry_count": len(self._index_entries),
            "last_sync": last_sync,
            "ttl_seconds": self.ttl_seconds,
        }
