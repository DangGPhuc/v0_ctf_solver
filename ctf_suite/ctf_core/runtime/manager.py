import fcntl
import json
import os
import re
import shutil
import unicodedata
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ..models import Challenge, CTFInfo


def sanitize_path_component(text: Any, default: str = "item") -> str:
    """
    Sanitize an input string to be a safe single filesystem component.
    Blocks '.', '..', path traversal, separators, and illegal characters.
    """
    if text is None:
        return default
    s = str(text).strip()
    if not s or s in [".", ".."]:
        return default

    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c))
    # Replace slashes, colons, dots sequences and dangerous path chars
    s = re.sub(r'[\s/\\:*?"<>|]+', "_", s)
    s = re.sub(r"\.{2,}", "_", s)  # prevent '..'
    s = re.sub(r"^[\._]+", "", s)   # strip leading dot or underscore
    s = re.sub(r"[_]+", "_", s).strip("_")
    return s or default


class RuntimeManager:
    """
    Manages the Ephemeral CTF Runtime directory.
    Target structure:
      <runtime_dir>/
      └── <event-id>/
          ├── event.json
          ├── .submitted_flags.jsonl
          └── challenges/
              └── <challenge-id>/
                  ├── input/       (immutable attachments/binaries)
                  ├── work/        (solve.py, logs, artifacts)
                  └── state.json   (lightweight state machine)
    """

    def __init__(self, base_dir: Optional[Path] = None, runtime_root: Optional[Path] = None):
        target_dir = base_dir or runtime_root
        if target_dir:
            self.base_dir = Path(target_dir).resolve()

        else:
            env_override = os.environ.get("CTF_RUNTIME_DIR")
            if env_override:
                self.base_dir = Path(env_override).resolve()
            else:
                # Default to <repo_root>/.runtime or current directory/.runtime
                # Finding repo root by ascending
                curr = Path.cwd().resolve()
                found_root = curr
                for parent in [curr, *curr.parents]:
                    if (parent / ".git").exists() or (parent / "ctf_suite").exists():
                        found_root = parent
                        break
                self.base_dir = (found_root / ".runtime").resolve()

        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _assert_contained(self, target_path: Path, expected_parent: Optional[Path] = None):
        """Strict containment guard preventing path traversal attacks."""
        resolved = target_path.resolve()
        parent = (expected_parent or self.base_dir).resolve()
        try:
            resolved.relative_to(parent)
        except ValueError:
            raise ValueError(
                f"Path traversal security violation: '{target_path}' is outside '{parent}'"
            )

    def event_path(self, event_id: str) -> Path:
        safe_eid = sanitize_path_component(event_id, default="default_event")
        p = self.base_dir / safe_eid
        self._assert_contained(p, self.base_dir)
        return p

    def start_event(self, event_id: str, event_info: Optional[CTFInfo] = None) -> Path:
        """Initialize an event workspace in .runtime/<event-id>/."""
        epath = self.event_path(event_id)
        epath.mkdir(parents=True, exist_ok=True)
        (epath / "challenges").mkdir(parents=True, exist_ok=True)

        event_file = epath / "event.json"
        if event_info and not event_file.is_file():
            data = event_info.model_dump()
            event_file.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        elif not event_file.is_file():
            initial_event = {
                "id": event_id,
                "title": f"Event {event_id}",
                "challenges": [],
            }
            event_file.write_text(json.dumps(initial_event, indent=2, ensure_ascii=False), encoding="utf-8")
        return epath

    def get_event_info(self, event_id: str) -> Optional[Dict[str, Any]]:
        epath = self.event_path(event_id)
        efile = epath / "event.json"
        if efile.is_file():
            try:
                return json.loads(efile.read_text(encoding="utf-8"))
            except Exception:
                return None
        return None

    def save_event_info(self, event_id: str, data: Dict[str, Any]) -> bool:
        epath = self.event_path(event_id)
        epath.mkdir(parents=True, exist_ok=True)
        efile = epath / "event.json"
        tmp_file = efile.with_suffix(".tmp")
        try:
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            shutil.move(str(tmp_file), str(efile))
            return True
        except Exception:
            if tmp_file.exists():
                tmp_file.unlink(missing_ok=True)
            return False

    def challenge_path(self, event_id: str, challenge_id: Any) -> Path:
        epath = self.event_path(event_id)
        safe_cid = sanitize_path_component(challenge_id, default="chall")
        cpath = epath / "challenges" / safe_cid
        self._assert_contained(cpath, epath / "challenges")
        return cpath

    def is_challenge_materialized(self, event_id: str, challenge_id: Any) -> bool:
        cpath = self.challenge_path(event_id, challenge_id)
        return (cpath / "state.json").is_file()

    def materialize_challenge(
        self,
        event_id: str,
        challenge: Challenge,
        download_fn: Optional[Callable[[Path], List[Path]]] = None,
    ) -> Path:
        """
        Lazily materializes a challenge:
        Creates input/, work/, and state.json.
        Downloads attachments only if download_fn is provided and input is empty.
        """
        epath = self.start_event(event_id)
        cpath = self.challenge_path(event_id, challenge.id)
        
        input_dir = cpath / "input"
        work_dir = cpath / "work"
        input_dir.mkdir(parents=True, exist_ok=True)
        work_dir.mkdir(parents=True, exist_ok=True)

        state_file = cpath / "state.json"
        if not state_file.is_file():
            initial_state = {
                "challenge_id": str(challenge.id),
                "name": challenge.name,
                "category": challenge.category,
                "points": challenge.points,
                "description": challenge.description,
                "connection_info": challenge.connection_info,
                "author": challenge.author,
                "tags": challenge.tags,
                "hints": challenge.hints,
                "status": "unsolved",
                "solved_by_me": challenge.solved_by_me,
                "iteration": 0,
                "flag_candidates": [],
                "flag": None,
                "active_hypothesis": None,
            }
            state_file.write_text(
                json.dumps(initial_state, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

        # Download attachments if input is currently empty
        if download_fn and not any(input_dir.iterdir()):
            download_fn(input_dir)

        # Generate standard solver template if not present
        cat = (challenge.category or "misc").lower()
        tpl_dir = Path(__file__).resolve().parent.parent / "execution" / "templates"
        tpl_path = tpl_dir / f"solve_{cat}.py"
        target_script = work_dir / "solve.py"
        if not tpl_path.is_file() and cat == "crypto":
            tpl_path = tpl_dir / "solve_crypto.sage"
            target_script = work_dir / "solve.sage"

        if not target_script.is_file() and not (work_dir / "solve.py").is_file():
            self._create_default_solve_script(target_script, tpl_path, challenge)

        return cpath

    def _create_default_solve_script(self, target: Path, tpl_path: Path, challenge: Challenge):
        host = ""
        port = ""
        conn = challenge.connection_info or ""
        if " " in conn:
            parts = conn.split()
            for i, p in enumerate(parts):
                if p in ["nc", "ncat", "netcat"] and i + 2 < len(parts):
                    host = parts[i + 1]
                    port = parts[i + 2]
                    break
        elif ":" in conn and not conn.startswith("http"):
            parts = conn.split(":")
            host = parts[0]
            port = parts[1]

        # Sanitize metadata to prevent code injection into generated solver scripts
        clean_comment_name = re.sub(r'[\r\n]+', ' ', str(challenge.name or "Unnamed"))
        clean_comment_cat = re.sub(r'[\r\n]+', ' ', str(challenge.category or "misc"))
        clean_comment_conn = re.sub(r'[\r\n]+', ' ', str(challenge.connection_info or "N/A"))

        safe_host_literal = json.dumps(host or "localhost")
        try:
            safe_port_literal = int(port) if port else 1337
        except (ValueError, TypeError):
            safe_port_literal = 1337

        safe_url_literal = json.dumps(conn if conn.startswith("http") else "")
        safe_name_literal = json.dumps(str(challenge.name or "challenge"))

        if tpl_path.is_file():
            content = tpl_path.read_text(encoding="utf-8")
            is_sage = tpl_path.suffix == ".sage"
            shebang = "#!/usr/bin/env sage\n" if is_sage else "#!/usr/bin/env python3\n"
            header = f"{shebang}# Solver for: {clean_comment_name} ({clean_comment_cat})\n# Connection: {clean_comment_conn}\n"
            if host:
                header += f'HOST = {safe_host_literal}\n'
            if port:
                header += f'PORT = {safe_port_literal}\n'
            header += f'TARGET_URL = {safe_url_literal}\n\n'
            for prefix in ["#!/usr/bin/env python3\n", "#!/usr/bin/env sage\n"]:
                if content.startswith(prefix):
                    content = content[len(prefix):]
            content = header + content
            target.write_text(content, encoding="utf-8")
            return

        content = f"""#!/usr/bin/env python3
# Solver for: {clean_comment_name} ({clean_comment_cat})
# Connection: {clean_comment_conn}
HOST = {safe_host_literal}
PORT = {safe_port_literal}
TARGET_URL = {safe_url_literal}

import sys
import os

def solve():
    print(f"[*] Running solver for {safe_name_literal}...")

if __name__ == "__main__":
    solve()
"""
        target.write_text(content, encoding="utf-8")

    def read_challenge_state(self, event_id: str, challenge_id: Any) -> Optional[Dict[str, Any]]:
        cpath = self.challenge_path(event_id, challenge_id)
        state_file = cpath / "state.json"
        if state_file.is_file():
            try:
                return json.loads(state_file.read_text(encoding="utf-8"))
            except Exception:
                return None
        return None

    def update_challenge_state(
        self, event_id: str, challenge_id: Any, mutator: Callable[[Dict[str, Any]], Dict[str, Any]]
    ) -> bool:
        cpath = self.challenge_path(event_id, challenge_id)
        state_file = cpath / "state.json"
        if not state_file.is_file():
            return False
        
        lock_file = cpath / ".state.lock"
        try:
            with open(lock_file, "w") as lf:
                fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
                try:
                    data = json.loads(state_file.read_text(encoding="utf-8"))
                    updated = mutator(data)
                    tmp_file = state_file.with_suffix(".tmp")
                    with open(tmp_file, "w", encoding="utf-8") as f:
                        json.dump(updated, f, indent=2, ensure_ascii=False)
                        f.flush()
                        os.fsync(f.fileno())
                    shutil.move(str(tmp_file), str(state_file))
                    return True
                finally:
                    fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
        except Exception:
            return False

    def write_challenge_state(self, event_id: str, challenge_id: Any, state: Dict[str, Any]) -> bool:
        """Write entire challenge state replacing previous dictionary."""
        return self.update_challenge_state(event_id, challenge_id, lambda _: state)

    def list_events(self) -> List[str]:
        if not self.base_dir.is_dir():
            return []
        events = []
        for d in self.base_dir.iterdir():
            if d.is_dir() and not d.name.startswith("."):
                events.append(d.name)
        return sorted(events)

    def list_materialized_challenges(self, event_id: str) -> List[Dict[str, Any]]:
        epath = self.event_path(event_id)
        chall_root = epath / "challenges"
        if not chall_root.is_dir():
            return []
        
        materialized = []
        for cdir in chall_root.iterdir():
            if cdir.is_dir() and not cdir.name.startswith("."):
                st = self.read_challenge_state(event_id, cdir.name)
                if st:
                    materialized.append(st)
                else:
                    materialized.append({"challenge_id": cdir.name, "path": str(cdir)})
        return materialized

    # ==========================================================================
    # CLEANUP POLICIES & METHODS
    # ==========================================================================

    def cleanup_challenge(self, event_id: str, challenge_id: Any, dry_run: bool = False) -> bool:
        """Deletes .runtime/<event-id>/challenges/<challenge-id>/ safely."""
        cpath = self.challenge_path(event_id, challenge_id)
        if not cpath.exists():
            return False
        if dry_run:
            return True
        shutil.rmtree(cpath, ignore_errors=True)
        return True

    def cleanup_event(self, event_id: str, dry_run: bool = False) -> bool:
        """Deletes .runtime/<event-id>/ safely."""
        epath = self.event_path(event_id)
        if not epath.exists():
            return False
        if dry_run:
            return True
        shutil.rmtree(epath, ignore_errors=True)
        return True

    def cleanup_all(self, dry_run: bool = False) -> List[Path]:
        """Deletes all events within runtime directory safely."""
        cleaned = []
        if not self.base_dir.is_dir():
            return cleaned
        for item in self.base_dir.iterdir():
            if item.is_dir() and not item.name.startswith("."):
                cleaned.append(item)
                if not dry_run:
                    shutil.rmtree(item, ignore_errors=True)
        return cleaned
