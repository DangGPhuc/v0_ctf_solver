import datetime
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from .tree import DiscoveryNode, DiscoveryTree


class KnowledgeCompiler:
    """
    Trích xuất và biên dịch kinh nghiệm thực chiến từ các bài CTF đã giải thành công
    (Winning Path & Dead-ends trong DiscoveryTree) thành Thẻ Tri Thức (Declarative Technique Cards).
    """

    def __init__(self, kb_dir: Optional[Path] = None):
        self.kb_dir = (
            Path(kb_dir).resolve()
            if kb_dir
            else Path(__file__).resolve().parents[2] / "knowledge_base"
        )
        self.cards_dir = self.kb_dir / "cards"
        self.cards_dir.mkdir(parents=True, exist_ok=True)
        self.index_file = self.kb_dir / "index.json"

    def compile_challenge(
        self,
        tree: DiscoveryTree,
        flag: Optional[str] = None,
        solver_code: Optional[str] = None,
        findings_text: Optional[str] = None,
    ) -> Path:
        """
        Trích xuất bài giải thành một Thẻ Tri Thức độc lập:
        - Winning Path (Chuỗi hành động thành công)
        - Dead-ends to Avoid (Các nhánh sai lầm đã thử và bị bác bỏ)
        - Reusable Snippets
        """
        winning_path = tree.get_winning_path() or []
        cat = tree.category.lower().strip()
        chall_name = tree.challenge_name or tree.challenge_id
        safe_name = re.sub(r"[^a-zA-Z0-9_\-]+", "_", chall_name).lower()

        # 1. Thu thập các nhánh chết đã bị cắt tỉa (Dead-ends)
        dead_ends = []
        for node in tree.nodes.values():
            if node.status in ["rejected", "pruned"]:
                reason = node.payload.get("diff") or node.payload.get("prune_reason") or "Thất bại"
                dead_ends.append(f"- **{node.name}**: {reason}")

        # 2. Thu thập chuỗi hành động chiến thắng
        winning_steps = []
        for idx, node in enumerate(winning_path[1:], 1):
            act_type = node.node_type.upper()
            details = node.payload.get("actions") or node.payload.get("observed") or node.name
            winning_steps.append(f"{idx}. **[{act_type}] {node.name}**: {details}")

        # 3. Tạo nội dung thẻ tri thức Markdown
        card_content = (
            f"# Declarative Technique Card: {chall_name}\n\n"
            f"- **Category**: {tree.category.upper()}\n"
            f"- **Challenge ID**: `{tree.challenge_id}`\n"
            f"- **Compiled At**: `{datetime.datetime.now().isoformat()}`\n"
            f"- **Flag Thu Hoạch**: `{flag or 'FLAG{...}'}`\n\n"
            f"---\n\n"
            f"## 1. Dấu Hiệu Nhận Diện (Indicators & Fingerprints)\n"
            f"{findings_text or '*Tham chiếu các đặc điểm tĩnh từ findings.md*'}\n\n"
            f"## 2. Chuỗi Tác Chiến Chiến Thắng (Winning Exploration Path)\n"
            f"{chr(10).join(winning_steps) if winning_steps else '*Không xác định được chuỗi chiến thắng hoàn chỉnh.*'}\n\n"
            f"## 3. Cạm Bẫy Cần Tránh (Anti-Patterns & Discarded Dead-Ends)\n"
            f"{chr(10).join(dead_ends) if dead_ends else '*Không ghi nhận nhánh bế tắc nào.*'}\n\n"
        )

        if solver_code:
            snippet = "\n".join(solver_code.splitlines()[:50])
            card_content += f"## 4. Mã Nguồn Solver Mẫu (Key Primitives)\n```python\n{snippet}\n```\n"

        # 4. Lưu thẻ vào thư mục category tương ứng
        cat_dir = self.cards_dir / cat
        cat_dir.mkdir(parents=True, exist_ok=True)
        card_path = cat_dir / f"{safe_name}.md"
        card_path.write_text(card_content, encoding="utf-8")

        # 5. Cập nhật index.json
        self._update_index(
            challenge_id=tree.challenge_id,
            challenge_name=chall_name,
            category=cat,
            card_path=card_path,
            has_flag=bool(flag),
        )

        return card_path

    def _update_index(
        self,
        challenge_id: str,
        challenge_name: str,
        category: str,
        card_path: Path,
        has_flag: bool,
    ):
        index = {}
        if self.index_file.exists():
            try:
                index = json.loads(self.index_file.read_text(encoding="utf-8"))
            except Exception:
                pass

        index[str(challenge_id)] = {
            "name": challenge_name,
            "category": category,
            "card_path": str(card_path.relative_to(self.kb_dir)),
            "has_flag": has_flag,
            "updated_at": datetime.datetime.now().isoformat(),
        }

        self.index_file.write_text(json.dumps(index, indent=2, ensure_ascii=False), encoding="utf-8")


class KnowledgeRetriever:
    """
    Truy vấn và chắt lọc các Thẻ Tri Thức liên quan theo Category và từ khóa
    để tiêm vào L1 Context khi giải bài mới, tránh hiện tượng prompt-stuffing.
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
