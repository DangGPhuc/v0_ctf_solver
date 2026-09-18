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

    def __init__(self, base_dir: Optional[Path] = None):
        if base_dir:
            self.base_dir = Path(base_dir).resolve()
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
        solve_py = work_dir / "solve.py"
        if not solve_py.is_file():
            self._create_default_solve_script(solve_py, challenge)

        return cpath

    def _create_default_solve_script(self, target: Path, challenge: Challenge):
        content = f"""#!/usr/bin/env python3
# Solver for: {challenge.name} ({challenge.category})
# Connection: {challenge.connection_info or "N/A"}
import sys
import os

def solve():
    print("[*] Running solver for {challenge.name}...")
    # Add exploit / solving logic here
    # Example:
    # flag = "FLAG{{...}}"
    # print(f"[+] Found flag: {{flag}}")
    # with open("flag.txt", "w") as f:
    #     f.write(flag + "\\n")

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
