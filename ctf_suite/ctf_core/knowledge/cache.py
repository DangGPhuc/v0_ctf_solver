import json
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

class KnowledgeCache:
    """
    On-demand local cache for remote knowledge indexes and YAML documents.
    Tracks metadata including cached_at timestamp and freshness TTL.
    """

    def __init__(self, base_dir: Optional[Path] = None, default_ttl_seconds: int = 900):
        self.base_dir = base_dir or (Path.home() / ".cache" / "v0_ctf_solver" / "knowledge")
        self.default_ttl_seconds = default_ttl_seconds
        self.indexes_dir = self.base_dir / "indexes"
        self.objects_dir = self.base_dir / "objects"
        self.indexes_dir.mkdir(parents=True, exist_ok=True)
        self.objects_dir.mkdir(parents=True, exist_ok=True)

    def _safe_name(self, repo: str, ref: str) -> str:
        return f"{repo.replace('/', '_')}_{ref.replace('/', '_')}"

    def _meta_path(self, repo: str, ref: str) -> Path:
        return self.indexes_dir / f"{self._safe_name(repo, ref)}_meta.json"

    def get_index_metadata(self, repo: str, ref: str) -> Optional[Dict[str, Any]]:
        mpath = self._meta_path(repo, ref)
        if mpath.is_file():
            try:
                return json.loads(mpath.read_text(encoding="utf-8"))
            except Exception:
                pass
        return None

    def is_index_fresh(self, repo: str, ref: str, ttl_seconds: Optional[int] = None) -> bool:
        """
        Determines whether the cached index is still fresh according to TTL.
        """
        idx_path = self.indexes_dir / f"{self._safe_name(repo, ref)}_index.jsonl"
        if not idx_path.is_file():
            return False

        meta = self.get_index_metadata(repo, ref)
        effective_ttl = ttl_seconds if ttl_seconds is not None else (meta.get("ttl_seconds", self.default_ttl_seconds) if meta else self.default_ttl_seconds)
        
        if meta and "cached_at_ts" in meta:
            age = time.time() - meta["cached_at_ts"]
            return age < effective_ttl

        # Fallback to mtime if meta is absent
        age = time.time() - idx_path.stat().st_mtime
        return age < effective_ttl

    def get_cached_index(self, repo: str, ref: str) -> Optional[List[Dict[str, Any]]]:
        idx_path = self.indexes_dir / f"{self._safe_name(repo, ref)}_index.jsonl"
        if not idx_path.is_file():
            return None
        entries = []
        try:
            with open(idx_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entries.append(json.loads(line))
            return entries
        except Exception:
            return None

    def store_index(self, repo: str, ref: str, entries: List[Dict[str, Any]], ttl_seconds: Optional[int] = None):
        idx_path = self.indexes_dir / f"{self._safe_name(repo, ref)}_index.jsonl"
        with open(idx_path, "w", encoding="utf-8") as f:
            for ent in entries:
                f.write(json.dumps(ent, ensure_ascii=False) + "\n")

        # Save metadata with timestamp and TTL
        meta = {
            "repo": repo,
            "ref": ref,
            "count": len(entries),
            "cached_at": datetime.now(timezone.utc).isoformat(),
            "cached_at_ts": time.time(),
            "ttl_seconds": ttl_seconds if ttl_seconds is not None else self.default_ttl_seconds,
        }
        self._meta_path(repo, ref).write_text(json.dumps(meta, indent=2), encoding="utf-8")

    def save_index(self, repo: str, ref: str, entries: List[Dict[str, Any]], ttl_seconds: Optional[int] = None):
        self.store_index(repo, ref, entries, ttl_seconds=ttl_seconds)

    def get_index(self, repo: str, ref: str) -> Optional[List[Dict[str, Any]]]:
        return self.get_cached_index(repo, ref)

    def _hash_key(self, key_or_sha: str, repo: Optional[str] = None) -> str:
        if repo:
            import hashlib
            return hashlib.sha256(f"{repo}:{key_or_sha}".encode()).hexdigest()
        return key_or_sha

    def get_object(self, key_or_sha: str, repo: Optional[str] = None) -> Optional[str]:
        if not key_or_sha:
            return None
        safe_key = self._hash_key(key_or_sha, repo)
        obj_path = self.objects_dir / f"{safe_key}.yaml"
        if obj_path.is_file():
            return obj_path.read_text(encoding="utf-8")
        return None

    def store_object(self, key_or_sha: str, content: str, repo: Optional[str] = None):
        if not key_or_sha or not content:
            return
        safe_key = self._hash_key(key_or_sha, repo)
        obj_path = self.objects_dir / f"{safe_key}.yaml"
        obj_path.write_text(content, encoding="utf-8")

    def save_object(self, repo: str, path: str, content: str):
        self.store_object(path, content, repo=repo)

    def clean(self):
        shutil.rmtree(self.base_dir, ignore_errors=True)
        self.indexes_dir.mkdir(parents=True, exist_ok=True)
        self.objects_dir.mkdir(parents=True, exist_ok=True)

    def get_stats(self) -> Dict[str, Any]:
        num_indices = len(list(self.indexes_dir.glob("*.jsonl")))
        num_objects = len(list(self.objects_dir.glob("*.yaml")))
        return {
            "cache_dir": str(self.base_dir),
            "cached_indices": num_indices,
            "cached_objects": num_objects,
        }
