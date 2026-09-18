import re
import yaml
from typing import Any, Dict, List, Optional, Protocol, Tuple

from .models import KnowledgeDocument, KnowledgeHit, KnowledgeQuery

def score_entry(entry: Dict[str, Any], query: KnowledgeQuery) -> Tuple[float, List[str]]:
    """
    Deterministic scoring algorithm for CTF technique cards.
    """
    score = 0.0
    matched_on = []

    status = entry.get("status", "active")
    if status == "candidate":
        return 0.0, []  # Exclude unvalidated candidates
    elif status == "legacy":
        score -= 5.0
        matched_on.append("status:legacy(-5)")

    # 1. Category exact match
    entry_cat = (entry.get("category") or "").lower()
    if query.category and query.category.lower() == entry_cat:
        score += 5.0
        matched_on.append(f"category:{entry_cat}(+5)")

    # 2. Tag intersection
    entry_tags = set(t.lower() for t in entry.get("tags", []))
    query_tags = set(t.lower() for t in query.tags)
    tag_hits = entry_tags.intersection(query_tags)
    if tag_hits:
        tag_score = min(len(tag_hits) * 4.0, 12.0)
        score += tag_score
        matched_on.append(f"tags:{list(tag_hits)}(+{tag_score})")

    # 3. File type matches
    signals = entry.get("signals", [])
    for ft in query.file_types:
        if any(ft.lower() in s.lower() for s in signals):
            score += 3.0
            matched_on.append(f"file_type:{ft}(+3)")

    # 4. Protection matches
    for prot in query.protections:
        if any(prot.lower() in s.lower() for s in signals):
            score += 3.0
            matched_on.append(f"protection:{prot}(+3)")

    # 5. Keyword search in title & summary
    title = (entry.get("title") or "").lower()
    summary = (entry.get("summary") or "").lower()
    for kw in query.keywords:
        kw_lower = kw.lower().strip()
        if not kw_lower:
            continue
        if kw_lower in title or kw_lower in summary:
            score += 3.0
            matched_on.append(f"keyword:{kw_lower}(+3)")

    # 6. Current hypothesis keyword boost
    if query.current_hypothesis:
        hyp_lower = query.current_hypothesis.lower()
        if any(w in hyp_lower for w in entry_tags):
            score += 4.0
            matched_on.append("hypothesis_tag_hit(+4)")

    return score, matched_on

class KnowledgeProvider(Protocol):
    def search(self, query: KnowledgeQuery, limit: int = 5) -> List[KnowledgeHit]:
        ...

    def fetch(self, hit_or_id: Any) -> Optional[KnowledgeDocument]:
        ...
