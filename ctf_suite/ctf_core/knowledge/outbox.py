import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml
from rich.console import Console

console = Console()

class KnowledgeOutbox:
    """
    Persistent local outbox for newly solved challenge candidates.
    Stored outside git at ~/.local/state/v0_ctf_solver/knowledge-outbox/.
    Ensures newly generated knowledge survives immediate runtime cleanup.
    """

    def __init__(self, outbox_dir: Optional[Path] = None):
        self.outbox_dir = outbox_dir or (Path.home() / ".local" / "state" / "v0_ctf_solver" / "knowledge-outbox")
        self.outbox_dir.mkdir(parents=True, exist_ok=True)

    def stage_candidate(
        self,
        challenge_id: Any,
        title: str,
        category: str,
        strategy: List[str],
        signals: Optional[List[str]] = None,
        preconditions: Optional[List[str]] = None,
        solve_script: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> Path:
        clean_name = title.lower()
        for prefix in ["pwn_", "crypto_", "rev_", "web_", "misc_", "devsecoops_", "devsecops_", "sanity_", "boot2root_", "pwn ", "crypto ", "rev ", "web ", "misc ", "pwn-", "crypto-", "rev-", "web-", "misc-"]:
            if clean_name.startswith(prefix):
                clean_name = clean_name[len(prefix):]
        tech_slug = re.sub(r"[^a-z0-9]+", "-", clean_name).strip("-") or str(challenge_id)
        cid = f"{category.lower()}.{tech_slug}"

        # Clean steps of any raw flags
        clean_steps = []
        for s in strategy:
            s_clean = re.sub(r"FLAG\{[^\n\r\}]+\}", "FLAG{<REDACTED>}", str(s))
            clean_steps.append(s_clean)

        candidate = {
            "schema_version": 1,
            "id": cid,
            "title": f"Technique: {title}",
            "kind": "technique",
            "category": category.lower(),
            "tags": tags or [category.lower()],
            "status": "candidate",
            "summary": f"Distilled pattern from {title}",
            "signals": signals or [f"Category match for {category}"],
            "preconditions": preconditions or [],
            "technique": {
                "steps": clean_steps
            },
            "verification": ["Verify recovered constraints against challenge oracle"],
            "failure_modes": ["Constraints unsolvable or mitigations active"],
            "version_constraints": [],
            "tool_hints": [],
            "reusable_snippets": [],
            "source_refs": [f"challenge_{challenge_id}"],
            "last_verified": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "quality": {
                "confidence": "medium",
                "reusable": True
            }
        }

        cand_file = self.outbox_dir / f"{cid}.yaml"
        cand_file.write_text(yaml.dump(candidate, sort_keys=False), encoding="utf-8")
        console.print(f"[bold green]✔ Staged knowledge candidate to outbox: [cyan]{cand_file}[/cyan][/bold green]")
        return cand_file

    def list_candidates(self) -> List[Dict[str, Any]]:
        candidates = []
        for ypath in sorted(self.outbox_dir.glob("*.yaml")):
            try:
                data = yaml.safe_load(ypath.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    data["file_path"] = str(ypath)
                    candidates.append(data)
            except Exception:
                pass
        return candidates

    def validate_candidate(self, candidate_path: Path) -> List[str]:
        errors = []
        text = candidate_path.read_text(encoding="utf-8")
        
        # 1. Plaintext flag checks
        if re.search(r"(?:FLAG|CTF|Null0rigin)\{[a-zA-Z0-9_\-]{4,}\}", text):
            errors.append("Plaintext flag found in candidate")

        # 2. Leaked tokens / credentials
        if re.search(r"(?:API_TOKEN|SESSION_COOKIE|REFRESH_TOKEN|Bearer\s+[a-zA-Z0-9_\-\.]{10,}|password\s*=)", text, re.IGNORECASE):
            errors.append("Leaked credentials found in candidate")

        try:
            data = yaml.safe_load(text)
            if not isinstance(data, dict):
                return ["Invalid YAML structure"]

            # 3. Taxonomy validation
            canonical_categories = [
                "pwn", "rev", "web", "crypto", "forensics",
                "hardware", "blockchain", "cloud", "ai", "misc", "boot2root"
            ]
            cat = str(data.get("category", "")).lower().strip()
            if cat not in canonical_categories:
                errors.append(f"Invalid category taxonomy: '{cat}'")

            # 4. Technique ID and low quality name checks
            cid = str(data.get("id", "")).lower()
            if "misc_happy" in cid or "happy" in cid:
                errors.append("Low quality card: generic happy challenge")
            if not cid or "." not in cid:
                errors.append(f"Invalid ID format: '{cid}', expected category.slug")

            # 5. Signals checks
            signals = data.get("signals", [])
            if not signals or not any(s.strip() for s in signals):
                errors.append("Empty or missing signals")

            # 6. Steps / Strategy quality check
            steps = data.get("technique", {}).get("steps", [])
            if not steps or not any(s.strip() for s in steps):
                errors.append("No technique steps provided")
            elif len(steps) == 1:
                step_text = steps[0].lower().strip()
                if step_text in ["static triage", "triage", "reverse engineering / static triage", "inspect binary"]:
                    errors.append("Low quality generic strategy: only static triage")

        except Exception as e:
            errors.append(f"YAML parsing error: {e}")

        return errors
