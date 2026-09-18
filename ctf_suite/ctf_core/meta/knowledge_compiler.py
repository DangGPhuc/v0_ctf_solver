import datetime
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml

from ..models import KnowledgeCard, KnowledgeCardFingerprint, KnowledgeCardSource
from .tree import DiscoveryNode, DiscoveryTree


from ..knowledge.outbox import KnowledgeOutbox

class KnowledgeCompiler:
    """
    Distills and compiles practical solving experience from solved CTF challenges
    into Declarative Technique Cards staged into local KnowledgeOutbox.
    
    CRITICAL: Never persists real flags, credentials, tokens, full binaries or raw logs.
    """

    def __init__(self, outbox: Optional[KnowledgeOutbox] = None, kb_dir: Optional[Path] = None):
        self.outbox = outbox or KnowledgeOutbox()
        # Fallback local directory for testing if needed
        self.kb_dir = Path(kb_dir).resolve() if kb_dir else None
        if self.kb_dir:
            self.cards_dir = self.kb_dir / "cards"
            self.cards_dir.mkdir(parents=True, exist_ok=True)
            self.index_file = self.kb_dir / "index.json"
        else:
            self.cards_dir = None
            self.index_file = None

    def _sanitize_id(self, text: str) -> str:
        s = re.sub(r"[^a-zA-Z0-9_\-]+", "_", text).strip("_").lower()
        return s or "card"

    def compile_card(
        self,
        challenge_id: Any,
        challenge_meta: Dict[str, Any],
        execution_history: Optional[List[Any]] = None,
        solve_script: Optional[str] = None,
    ) -> Path:
        name = challenge_meta.get("name", f"Challenge_{challenge_id}")
        category = challenge_meta.get("category", "misc")
        tags = challenge_meta.get("tags", [])
        signals = challenge_meta.get("findings", [])
        strategy = challenge_meta.get("strategy", ["Execute verified exploit payload"])

        return self.outbox.stage_candidate(
            challenge_id=challenge_id,
            title=name,
            category=category,
            strategy=strategy,
            signals=signals,
            solve_script=solve_script,
            tags=tags,
        )

    def compile_challenge(
        self,
        tree: DiscoveryTree,
        flag: Optional[str] = None,
        solver_code: Optional[str] = None,
        findings_text: Optional[str] = None,
        fingerprint_info: Optional[Dict[str, Any]] = None,
    ) -> Path:
        """
        Distills a solved challenge into a clean KnowledgeCard without secrets or real flags.
        """
        winning_path = tree.get_winning_path() or []
        cat = tree.category.lower().strip()
        chall_name = tree.challenge_name or tree.challenge_id
        safe_id = self._sanitize_id(f"{cat}_{chall_name}")

        # 1. Collect pruned dead-ends
        failure_modes = []
        for node in tree.nodes.values():
            if node.status in ["rejected", "pruned"]:
                reason = node.payload.get("diff") or node.payload.get("prune_reason") or "Failed attempt"
                failure_modes.append(f"{node.name}: {reason}")

        # 2. Collect winning strategy steps
        strategy_steps = []
        for idx, node in enumerate(winning_path[1:], 1):
            act_type = node.node_type.upper()
            details = node.payload.get("actions") or node.payload.get("observed") or node.name
            # Mask any flag patterns in details
            cleaned_details = re.sub(r'(?i)(?:flag|ctf|nns|null0rigin)\{[^\}\r\n]+\}', 'FLAG{...}', str(details))
            strategy_steps.append(f"[{act_type}] {node.name}: {cleaned_details}")

        # 3. Extract reusable snippet (function / primitive only, not full exploit)
        reusable_snippets = []
        if solver_code:
            lines = solver_code.splitlines()
            clean_lines = []
            for l in lines[:40]:
                if any(kw in l for kw in ["password", "token", "cookie", "secret", "FLAG"]):
                    continue
                clean_lines.append(l)
            if clean_lines:
                reusable_snippets.append("\n".join(clean_lines))

        # Fingerprint & Signals
        fp = KnowledgeCardFingerprint(
            file_types=fingerprint_info.get("file_types", []) if fingerprint_info else [],
            protections=fingerprint_info.get("protections", []) if fingerprint_info else [],
            tags=fingerprint_info.get("tags", [cat]) if fingerprint_info else [cat],
        )

        signals = []
        if findings_text:
            for line in findings_text.splitlines():
                line = line.strip().lstrip("-* ").strip()
                if line and len(line) < 120 and not any(kw in line.lower() for kw in ["flag{", "token", "cookie"]):
                    signals.append(line)
        signals = signals[:5]

        chall_hash = hashlib.sha256(f"{chall_name}:{cat}".encode("utf-8")).hexdigest()[:16]

        card = KnowledgeCard(
            id=safe_id,
            title=chall_name,
            category=cat,
            fingerprint=fp,
            signals=signals,
            primitive=f"Standard {cat.upper()} exploitation primitive",
            preconditions=[],
            strategy=strategy_steps or ["Initial static triage", "Targeted payload construction"],
            verification=["Verify response or state transition in solver"],
            failure_modes=failure_modes[:5],
            reusable_snippets=reusable_snippets,
            source=KnowledgeCardSource(
                challenge_hash=chall_hash,
                learned_at=datetime.datetime.now().isoformat(),
            ),
        )

        outbox_file = self.outbox.stage_candidate(
            challenge_id=tree.challenge_id,
            title=chall_name,
            category=cat,
            strategy=strategy_steps or ["Initial static triage", "Targeted payload construction"],
            signals=signals,
            preconditions=[],
            solve_script=solver_code,
            tags=fp.tags,
        )

        if self.cards_dir and self.index_file:
            cat_dir = self.cards_dir / cat
            cat_dir.mkdir(parents=True, exist_ok=True)
            card_file = cat_dir / f"{safe_id}.yaml"
            card_dict = card.model_dump()
            card_file.write_text(yaml.safe_dump(card_dict, sort_keys=False, allow_unicode=True), encoding="utf-8")
            self._update_index(
                challenge_id=tree.challenge_id,
                challenge_name=chall_name,
                category=cat,
                card_path=card_file,
                card_id=safe_id,
            )
            return card_file

        return outbox_file

    def _update_index(
        self,
        challenge_id: str,
        challenge_name: str,
        category: str,
        card_path: Path,
        card_id: str,
    ):
        index = {}
        if self.index_file.exists():
            try:
                index = json.loads(self.index_file.read_text(encoding="utf-8"))
            except Exception:
                pass

        index[str(challenge_id)] = {
            "id": card_id,
            "name": challenge_name,
            "category": category,
            "card_path": str(card_path.relative_to(self.kb_dir)),
            "updated_at": datetime.datetime.now().isoformat(),
        }

        self.index_file.write_text(json.dumps(index, indent=2, ensure_ascii=False), encoding="utf-8")

    def migrate_saved_notes(self, notes_file: Path) -> int:
        """
        Parses SAVED_NOTES.md and distills challenges into structured KnowledgeCards.
        Ensures NO real flags or credentials are stored.
        """
        if not notes_file.is_file():
            return 0

        content = notes_file.read_text(encoding="utf-8")
        # Split by ## Solved Challenge: `<name>`
        sections = re.split(r"\n##\s+Solved Challenge:\s*", content)
        count = 0

        for sec in sections[1:]:
            lines = sec.strip().splitlines()
            if not lines:
                continue
            title_line = lines[0].strip().strip("`")
            chall_name = title_line
            cat = "misc"

            category_match = re.search(r"-\s+\*\*Category\*\*:\s*([^\n]+)", sec)
            if category_match:
                cat = category_match.group(1).strip().lower().split("/")[0].strip()

            target_file_match = re.search(r"-\s+\*\*Target File\*\*:\s*([^\n]+)", sec)
            target_file = target_file_match.group(1).strip() if target_file_match else None

            # Extract analysis points
            strategy = []
            snippets = []
            analysis_start = False
            code_block = False
            curr_code = []

            for line in lines:
                if "**Analysis**:" in line:
                    analysis_start = True
                    continue
                if analysis_start:
                    if line.strip().startswith("```"):
                        if code_block:
                            code_block = False
                            if curr_code:
                                snippets.append("\n".join(curr_code))
                                curr_code = []
                        else:
                            code_block = True
                        continue
                    if code_block:
                        curr_code.append(line)
                    else:
                        cleaned = line.strip().lstrip("-* ").strip()
                        # Strip any flags
                        cleaned = re.sub(r'(?i)(?:flag|ctf|nns|null0rigin)\{[^\}\r\n]+\}', 'FLAG{...}', cleaned)
                        if cleaned and not cleaned.startswith("**Status**"):
                            strategy.append(cleaned)

            safe_id = self._sanitize_id(f"{cat}_{chall_name}")
            fp = KnowledgeCardFingerprint(
                file_types=[target_file] if target_file else [],
                tags=[cat],
            )
            card = KnowledgeCard(
                id=safe_id,
                title=chall_name,
                category=cat,
                fingerprint=fp,
                signals=[f"Target: {target_file}"] if target_file else [],
                primitive=f"Distilled technique from {chall_name}",
                strategy=strategy[:8] if strategy else ["Reverse engineering / static triage"],
                verification=["Check verification logic against recovered constraints"],
                failure_modes=[],
                reusable_snippets=snippets[:2],
                source=KnowledgeCardSource(
                    challenge_hash=hashlib.sha256(chall_name.encode()).hexdigest()[:16],
                    learned_at=datetime.datetime.now().isoformat(),
                ),
            )

            cat_dir = self.cards_dir / cat
            cat_dir.mkdir(parents=True, exist_ok=True)
            card_path = cat_dir / f"{safe_id}.yaml"
            card_path.write_text(yaml.safe_dump(card.model_dump(), sort_keys=False, allow_unicode=True), encoding="utf-8")

            self._update_index(
                challenge_id=safe_id,
                challenge_name=chall_name,
                category=cat,
                card_path=card_path,
                card_id=safe_id,
            )
            count += 1

        return count


class KnowledgeRetriever:
    """
    Retrieves and filters relevant KnowledgeCards to inject into context.
    """

    def __init__(self, kb_dir: Optional[Path] = None):
        self.kb_dir = (
            Path(kb_dir).resolve()
            if kb_dir
            else Path(__file__).resolve().parents[2] / "knowledge_base"
        )
        self.cards_dir = self.kb_dir / "cards"
        self.index_file = self.kb_dir / "index.json"

    def retrieve_relevant_cards(self, category: str, keywords: Optional[List[str]] = None, max_cards: int = 2) -> List[Dict[str, Any]]:
        if not self.index_file.exists():
            return []

        try:
            index = json.loads(self.index_file.read_text(encoding="utf-8"))
        except Exception:
            return []

        cat_clean = category.lower().strip()
        matched = []

        for cid, meta in index.items():
            if meta.get("category", "").lower() == cat_clean:
                card_rel = meta.get("card_path")
                if card_rel:
                    card_full = self.kb_dir / card_rel
                    if card_full.is_file():
                        matched.append({
                            "challenge_id": cid,
                            "name": meta.get("name"),
                            "category": cat_clean,
                            "card_path": card_full,
                            "content": card_full.read_text(encoding="utf-8"),
                        })

        return matched[:max_cards]
