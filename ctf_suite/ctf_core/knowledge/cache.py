import json
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

class KnowledgeCache:
    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or (Path.home() / ".cache" / "v0_ctf_solver" / "knowledge")
        self.indexes_dir = self.base_dir / "indexes"
        self.objects_dir = self.base_dir / "objects"
        self.indexes_dir.mkdir(parents=True, exist_ok=True)
        self.objects_dir.mkdir(parents=True, exist_ok=True)

    def _safe_name(self, repo: str, ref: str) -> str:
        return f"{repo.replace('/', '_')}_{ref}"

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

    def store_index(self, repo: str, ref: str, entries: List[Dict[str, Any]]):
        idx_path = self.indexes_dir / f"{self._safe_name(repo, ref)}_index.jsonl"
        with open(idx_path, "w", encoding="utf-8") as f:
            for ent in entries:
                f.write(json.dumps(ent, ensure_ascii=False) + "\n")

    def save_index(self, repo: str, ref: str, entries: List[Dict[str, Any]]):
        self.store_index(repo, ref, entries)

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
