import datetime
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.tree import Tree


@dataclass
class DiscoveryNode:
    """Đại diện cho một nút trong Cây Khám Phá (Discovery Tree / DAG)."""
    node_id: str
    parent_id: Optional[str]
    children_ids: List[str] = field(default_factory=list)
    actor: str = "executor"  # system, advisor, executor, evaluator
    node_type: str = "action"  # root, hypothesis, action, observation, terminal_flag, pruned_dead_end, escalation
    name: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)
    cost: Dict[str, Any] = field(default_factory=lambda: {"time_seconds": 0.0, "tool_calls": 0, "tokens": 0})
    status: str = "active"  # active, confirmed, rejected, pruned, solved
    timestamp: str = field(default_factory=lambda: datetime.datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DiscoveryNode":
        return cls(**data)


class DiscoveryTree:
    """
    Cây Khám Phá (DAG) đại diện cho toàn bộ không gian tìm kiếm thực tế (Realized Search Space)
    của một bài tập CTF qua các vòng lặp giữa Advisor và Executor.
    """

    def __init__(self, challenge_id: str, challenge_name: str = "", category: str = "Misc"):
        self.challenge_id = str(challenge_id)
        self.challenge_name = challenge_name
        self.category = category
        self.root_id = f"root_{challenge_id}"
        self.nodes: Dict[str, DiscoveryNode] = {}
        self.created_at = datetime.datetime.now().isoformat()
        self.last_updated = self.created_at

        # Tự động tạo nút ROOT nếu cây mới
        root_node = DiscoveryNode(
            node_id=self.root_id,
            parent_id=None,
            actor="system",
            node_type="root",
            name=f"Root: {challenge_name or challenge_id}",
            payload={"challenge_id": self.challenge_id, "category": self.category},
            status="active",
        )
        self.nodes[self.root_id] = root_node

    def add_node(self, node: DiscoveryNode) -> DiscoveryNode:
        """Thêm một nút vào cây và liên kết với nút cha."""
        self.nodes[node.node_id] = node
        if node.parent_id and node.parent_id in self.nodes:
            parent = self.nodes[node.parent_id]
            if node.node_id not in parent.children_ids:
                parent.children_ids.append(node.node_id)
        self.last_updated = datetime.datetime.now().isoformat()
        return node

    def get_node(self, node_id: str) -> Optional[DiscoveryNode]:
        return self.nodes.get(node_id)

    def get_children(self, node_id: str) -> List[DiscoveryNode]:
        node = self.get_node(node_id)
        if not node:
            return []
        return [self.nodes[cid] for cid in node.children_ids if cid in self.nodes]

    def get_path_to_node(self, node_id: str) -> List[DiscoveryNode]:
        """Truy ngược đường đi từ Root đến nút chỉ định."""
        path = []
        curr = self.get_node(node_id)
        while curr:
            path.append(curr)
            if curr.parent_id:
                curr = self.get_node(curr.parent_id)
            else:
                break
        path.reverse()
        return path

    def get_winning_path(self) -> Optional[List[DiscoveryNode]]:
        """Tìm đường đi dẫn tới chiến thắng (nút terminal_flag hoặc status solved)."""
        for node in self.nodes.values():
            if node.node_type == "terminal_flag" or node.status == "solved":
                return self.get_path_to_node(node.node_id)
        return None

    def prune_subtree(self, node_id: str, reason: str = "Dead end rejected"):
        """Cắt tỉa một nhánh bế tắc và đánh dấu toàn bộ con cháu là pruned."""
        target = self.get_node(node_id)
        if not target:
            return
        target.status = "pruned"
        target.node_type = "pruned_dead_end"
        target.payload["prune_reason"] = reason

        stack = list(target.children_ids)
        while stack:
            cid = stack.pop()
            cnode = self.get_node(cid)
            if cnode:
                cnode.status = "pruned"
                stack.extend(cnode.children_ids)
        self.last_updated = datetime.datetime.now().isoformat()

    def get_active_leaves(self) -> List[DiscoveryNode]:
        """Lấy tất cả các nút lá đang còn hoạt động (chưa bị pruned hay solved)."""
        leaves = []
        for node in self.nodes.values():
            if not node.children_ids and node.status in ["active", "confirmed"]:
                leaves.append(node)
        return leaves

    def to_dict(self) -> Dict[str, Any]:
        return {
            "challenge_id": self.challenge_id,
            "challenge_name": self.challenge_name,
            "category": self.category,
            "root_id": self.root_id,
            "created_at": self.created_at,
            "last_updated": self.last_updated,
            "total_nodes": len(self.nodes),
            "nodes": {nid: node.to_dict() for nid, node in self.nodes.items()},
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DiscoveryTree":
        tree = cls(
            challenge_id=data.get("challenge_id", "unknown"),
            challenge_name=data.get("challenge_name", ""),
            category=data.get("category", "Misc"),
        )
        tree.root_id = data.get("root_id", tree.root_id)
        tree.created_at = data.get("created_at", tree.created_at)
        tree.last_updated = data.get("last_updated", tree.last_updated)
        tree.nodes = {}
        for nid, ndata in data.get("nodes", {}).items():
            tree.nodes[nid] = DiscoveryNode.from_dict(ndata)
        return tree

    def save(self, filepath: Path):
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")

    @classmethod
    def load(cls, filepath: Path) -> "DiscoveryTree":
        filepath = Path(filepath)
        if not filepath.is_file():
            raise FileNotFoundError(f"Không tìm thấy file cây khám phá: {filepath}")
        data = json.loads(filepath.read_text(encoding="utf-8"))
        return cls.from_dict(data)

    def render_rich_tree(self) -> Tree:
        """Tạo đối tượng Rich Tree trực quan để in ra Terminal."""
        root_node = self.nodes.get(self.root_id)
        label = f"[bold cyan]🎯 Discovery Tree: {self.challenge_name or self.challenge_id}[/bold cyan] ({self.category})"
        rich_tree = Tree(label)

        if not root_node:
            return rich_tree

        def _add_children(parent_node: DiscoveryNode, parent_ui: Tree):
            for cid in parent_node.children_ids:
                cnode = self.nodes.get(cid)
                if not cnode:
                    continue

                # Styling theo type và status
                icon = "⚙️"
                color = "white"
                if cnode.node_type == "hypothesis":
                    icon = "💡"
                    color = "yellow"
                elif cnode.node_type == "action":
                    icon = "⚡"
                    color = "blue"
                elif cnode.node_type == "observation":
                    icon = "👁️"
                    color = "cyan"
                elif cnode.node_type == "terminal_flag":
                    icon = "🚩"
                    color = "bold green"
                elif cnode.node_type == "pruned_dead_end" or cnode.status == "pruned":
                    icon = "❌"
                    color = "dim red"
                elif cnode.node_type == "escalation":
                    icon = "🚨"
                    color = "magenta"

                status_tag = f"[{cnode.status.upper()}]" if cnode.status != "active" else ""
                node_label = f"{icon} [{color}][bold]{cnode.name or cnode.node_id}[/bold] {status_tag}[/{color}]"
                
                # Thêm chi tiết tóm tắt nếu có
                if cnode.node_type == "action" and "actions" in cnode.payload:
                    act = cnode.payload.get("actions", "")
                    node_label += f" [dim]({act[:40]}...)[/dim]" if len(act) > 40 else f" [dim]({act})[/dim]"
                elif cnode.node_type == "observation" and "observed" in cnode.payload:
                    obs = cnode.payload.get("observed", "")
                    node_label += f" [dim italic]➔ {obs[:45]}...[/dim italic]" if len(obs) > 45 else f" [dim italic]➔ {obs}[/dim italic]"

                child_ui = parent_ui.add(node_label)
                _add_children(cnode, child_ui)

        _add_children(root_node, rich_tree)
        return rich_tree
