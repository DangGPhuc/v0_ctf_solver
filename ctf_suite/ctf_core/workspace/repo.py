import fcntl
import json
import os
import shutil
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional
from ..models import CTFInfo, Challenge

class WorkspaceRepo:
    """
    Quản lý truy cập file tập trung và bảo đảm an toàn đa tiến trình (File Locking).
    Đảm bảo việc cập nhật challenges.json và metadata.json luôn nhất quán.
    """
    def __init__(self, workspace_root: Path):
        self.root = Path(workspace_root).resolve()
        self.challenges_file = self.root / "challenges.json"
        self.summary_file = self.root / "SUMMARY.md"
        self.env_file = self.root / ".env"

    def read_challenges(self) -> Optional[Dict[str, Any]]:
        if not self.challenges_file.is_file():
            return None
        try:
            with open(self.challenges_file, "r", encoding="utf-8") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                try:
                    return json.load(f)
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except Exception:
            return None

    def write_challenges(self, data: Dict[str, Any]) -> bool:
        self.root.mkdir(parents=True, exist_ok=True)
        tmp_file = self.challenges_file.with_suffix(".tmp")
        try:
            with open(tmp_file, "w", encoding="utf-8") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                    f.flush()
                    os.fsync(f.fileno())
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            shutil.move(str(tmp_file), str(self.challenges_file))
            return True
        except Exception:
            if tmp_file.exists():
                tmp_file.unlink(missing_ok=True)
            return False

    def update_challenges(self, mutator: Callable[[Dict[str, Any]], Dict[str, Any]]) -> bool:
        lock_path = self.root / ".challenges.lock"
        with open(lock_path, "w") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            try:
                data = self.read_challenges() or {"ctf_info": {}, "challenges": []}
                updated = mutator(data)
                return self.write_challenges(updated)
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)

    def iter_challenge_dirs(self) -> Iterator[Path]:
        """
        Duyệt qua tất cả thư mục challenge hợp lệ (chứa challenge/metadata.json).
        """
        if not self.root.is_dir():
            return
        for cat_dir in self.root.iterdir():
            if not cat_dir.is_dir() or cat_dir.name.startswith("."):
                continue
            for chall_dir in cat_dir.iterdir():
                if not chall_dir.is_dir() or chall_dir.name.startswith("."):
                    continue
                meta = chall_dir / "challenge" / "metadata.json"
                if meta.is_file():
                    yield chall_dir

    def read_challenge_metadata(self, chall_dir: Path) -> Optional[Dict[str, Any]]:
        meta_file = chall_dir / "challenge" / "metadata.json"
        if not meta_file.is_file():
            return None
        try:
            with open(meta_file, "r", encoding="utf-8") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                try:
                    return json.load(f)
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except Exception:
            return None

    def write_challenge_metadata(self, chall_dir: Path, data: Dict[str, Any]) -> bool:
        meta_file = chall_dir / "challenge" / "metadata.json"
        meta_file.parent.mkdir(parents=True, exist_ok=True)
        tmp_file = meta_file.with_suffix(".tmp")
        try:
            with open(tmp_file, "w", encoding="utf-8") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                    f.flush()
                    os.fsync(f.fileno())
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            shutil.move(str(tmp_file), str(meta_file))
            return True
        except Exception:
            if tmp_file.exists():
                tmp_file.unlink(missing_ok=True)
            return False

    def find_challenge_dir(self, challenge_id: Any) -> Optional[Path]:
        cid_str = str(challenge_id).strip().lower()
        for cdir in self.iter_challenge_dirs():
            if cdir.name.lower() == cid_str:
                return cdir
            meta = self.read_challenge_metadata(cdir)
            if meta:
                mid = str(meta.get("id", "")).strip().lower()
                mname = str(meta.get("name", "")).strip().lower()
                if mid == cid_str or mname == cid_str:
                    return cdir
        return None

    def mark_challenge_solved(self, challenge_id: Any, flag: str) -> bool:
        cid_str = str(challenge_id).strip()
        # 1. Update in challenges.json
        def _mut(data: Dict[str, Any]) -> Dict[str, Any]:
            for c in data.get("challenges", []):
                if str(c.get("id", "")).strip() == cid_str:
                    c["solved_by_me"] = True
                    c["flag"] = flag
            return data
        self.update_challenges(_mut)

        # 2. Update in challenge metadata.json & write flag.txt
        cdir = self.find_challenge_dir(challenge_id)
        if cdir:
            meta = self.read_challenge_metadata(cdir) or {}
            meta["solved_by_me"] = True
            meta["flag"] = flag
            self.write_challenge_metadata(cdir, meta)
            
            # Save flag.txt in solver/ and challenge/
            for sub in ["solver", "challenge"]:
                flag_file = cdir / sub / "flag.txt"
                flag_file.write_text(flag + "\n", encoding="utf-8")
        return True
