import json
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import KnowledgeDocument, KnowledgeHit, KnowledgeQuery
from .provider import score_entry

class LocalKnowledgeProvider:
    def __init__(self, root_dir: Path):
        self.root_dir = Path(root_dir).resolve()
        self.index_path = self.root_dir / "index.jsonl"
        self._index_entries: List[Dict[str, Any]] = []
        self._load_index()

    def _load_index(self):
        if not self.index_path.is_file():
            return
        entries = []
        with open(self.index_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        self._index_entries = entries

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

        card_file = self.root_dir / rel_path
        if not card_file.is_file():
            return None

        content = card_file.read_text(encoding="utf-8")
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            return None

        tech = data.get("technique", {})
        steps = tech.get("steps", []) if isinstance(tech, dict) else []

        return KnowledgeDocument(
            id=data.get("id", cid or ""),
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
