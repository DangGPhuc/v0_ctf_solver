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
    On-demand 'Drive mode' knowledge provider accessing GitHub repository.
    Does NOT clone repository. Fetches and caches index and individual documents.
    """

    def __init__(
        self,
        repo: str = "DangGPhuc/v0_ctf_knowledge",
        ref: str = "main",
        cache: Optional[KnowledgeCache] = None,
        offline: bool = False
    ):
        self.repo = repo
        self.ref = ref
        self.cache = cache or KnowledgeCache()
        self.offline = offline
        self.token = self._resolve_token()
        self._index_entries: List[Dict[str, Any]] = []
        self._load_or_sync_index()

    def _resolve_token(self) -> Optional[str]:
        # 1. Environment variable
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if token:
            return token
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
        headers = {"User-Agent": "v0-ctf-solver/2.0"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _load_or_sync_index(self):
        # 1. Try local cache first
        cached = self.cache.get_cached_index(self.repo, self.ref)
        if cached:
            self._index_entries = cached
            return

        if self.offline:
            return

        # 2. Sync from GitHub API / Raw
        self.sync_index()

    def sync_index(self) -> bool:
        """Download latest index.jsonl from GitHub and update local cache."""
        if self.offline:
            console.print("[yellow]⚠️ Running in offline mode; skipping remote knowledge sync.[/yellow]")
            return False

        # GitHub raw URL for index.jsonl
        url = f"https://raw.githubusercontent.com/{self.repo}/{self.ref}/index.jsonl"
        console.print(f"[dim]🌐 Fetching knowledge index from {self.repo}:{self.ref}...[/dim]")

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
                    self.cache.store_index(self.repo, self.ref, entries)
                    console.print(f"[bold green]✔ Successfully synced {len(entries)} knowledge index entries![/bold green]")
                    return True
                else:
                    console.print(f"[yellow]⚠️ Failed to fetch index ({res.status_code}): {res.text[:100]}. Solver will continue without remote index.[/yellow]")
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

        # 2. Fetch on-demand from remote
        url = f"https://raw.githubusercontent.com/{self.repo}/{self.ref}/{rel_path}"
        try:
            with httpx.Client(timeout=10.0, headers=self._get_headers(), follow_redirects=True) as client:
                res = client.get(url)
                if res.status_code == 200:
                    content = res.text
                    if blob_sha:
                        self.cache.store_object(blob_sha, content)
                    self.cache.store_object(rel_path, content, repo=self.repo)
                    return self._parse_document(content, cid or "", blob_sha)
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
