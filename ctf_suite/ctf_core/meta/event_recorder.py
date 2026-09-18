import datetime
import json
from pathlib import Path
from typing import Any, Dict, Optional

from .tree import DiscoveryNode, DiscoveryTree


class EventRecorder:
    """
    Ghi nhận luồng sự kiện thời gian thực vào events.jsonl và đồng bộ liên tục
    vào cấu trúc Cây Khám Phá (DiscoveryTree) lưu tại tree.json.
    """

    def __init__(self, advisor_dir: Path, tree: Optional[DiscoveryTree] = None):
        self.advisor_dir = Path(advisor_dir).resolve()
        self.events_file = self.advisor_dir / "events.jsonl"
        self.tree_file = self.advisor_dir / "tree.json"

        if tree:
            self.tree = tree
        elif self.tree_file.exists():
            self.tree = DiscoveryTree.load(self.tree_file)
        else:
            self.tree = DiscoveryTree(challenge_id=self.advisor_dir.parent.name)

        self.event_counter = self._count_existing_events()

    def _count_existing_events(self) -> int:
        if not self.events_file.exists():
            return 0
        try:
            return sum(1 for line in self.events_file.read_text(encoding="utf-8").splitlines() if line.strip())
        except Exception:
            return 0

    def record_event(
        self,
        event_type: str,
        actor: str,  # advisor, executor, evaluator, system
        parent_id: Optional[str] = None,
        node_id: Optional[str] = None,
        node_name: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
        cost: Optional[Dict[str, Any]] = None,
        status: str = "active",
    ) -> DiscoveryNode:
        """
        Ghi 1 sự kiện vào events.jsonl và cập nhật 1 nút tương ứng vào DiscoveryTree.
        """
        self.event_counter += 1
        evt_id = f"evt_{self.event_counter:04d}"
        now = datetime.datetime.now().isoformat()
        payload = payload or {}
        cost = cost or {"time_seconds": 0.0, "tool_calls": 0, "tokens": 0}

        # Nút cha mặc định là root_id nếu không được chỉ định
        parent_node_id = parent_id or self.tree.root_id

        # Node id tạo mới nếu chưa có
        nid = node_id or f"node_{self.event_counter:04d}_{event_type}"
        name = node_name or f"{event_type.replace('_', ' ').title()}"

        # 1. Tạo hoặc cập nhật node trong DiscoveryTree
        node = self.tree.get_node(nid)
        if not node:
            node = DiscoveryNode(
                node_id=nid,
                parent_id=parent_node_id,
                actor=actor,
                node_type=event_type,
                name=name,
                payload=payload,
                cost=cost,
                status=status,
                timestamp=now,
            )
            self.tree.add_node(node)
        else:
            node.payload.update(payload)
            node.status = status
            node.cost["time_seconds"] += cost.get("time_seconds", 0.0)
            node.cost["tool_calls"] += cost.get("tool_calls", 0)
            node.cost["tokens"] += cost.get("tokens", 0)

        # 2. Ghi append vào events.jsonl
        event_record = {
            "event_id": evt_id,
            "timestamp": now,
            "event_type": event_type,
            "actor": actor,
            "parent_id": parent_node_id,
            "node_id": nid,
            "status": status,
            "cost": cost,
            "payload": payload,
        }

        with open(self.events_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(event_record, ensure_ascii=False) + "\n")

        # 3. Đồng bộ tree.json
        self.tree.save(self.tree_file)
        return node
