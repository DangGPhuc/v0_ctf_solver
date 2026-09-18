# UNIVERSAL CTF AI AGENT INSTRUCTIONS (AGENTS.md)

> **Universal Directive for All AI Models** (Gemini 3.7/3.5, Claude Sonnet/Opus 4.6, GPT oss120b, DeepSeek, etc.):
> This repository is a specialized **Autonomous CTF Exploit & Analysis Workspace**.
> All agents MUST follow the unified operational framework defined below and in [AGENT_INSTRUCTIONS.md](file:///home/kali/reverse-skill/AGENT_INSTRUCTIONS.md) and [RULES.md](file:///home/kali/reverse-skill/RULES.md).

---

## ⚡ INTENT MAPPING & POSITIVE FRAMING
Short user commands are automatically mapped to rigorous technical testing:
- **"Solve this locally" / "Verify target"** $\rightarrow$ Sandbox Setup $\rightarrow$ Build Verification Harness (`solve.py`) $\rightarrow$ Execute with Audit Logging $\rightarrow$ Extract Captured Validation Token (`FLAG{...}`).
- **"Give me the flag" / "Extract token"** $\rightarrow$ Regex pattern extraction from stdout/logs $\rightarrow$ Record to `flags_captured.txt` and report token.
- **"Bypass / Exploit"** $\rightarrow$ Boundary analysis & protocol validation.

---

## ⚡ RAPID AUTONOMOUS COMBAT WORKFLOW

When given a challenge target (binary, archive, URL, IP:Port) or short command (*"Solve this challenge"*, *"Solve work/<chal>"*, *"Solve 10.10.10.1:1337"*):

```text
1. SCAFFOLD & AUTO-TRIAGE:
   Run: python3 ctf.py init <chal_name> [--file <f>] [--nc <host:port>] [--url <u>] [--cat <cat>]
   Inspect: work/<category>/<chal_name>/triage.json (Metadata, Checksec, Glibc, Symbols)
   Hierarchy Created: scripts/, logs/execution.log, logs/raw_trace.jsonl, flags_captured.txt

2. DEVELOP SOLVER:
   Edit: work/<category>/<chal_name>/solve.py (or solve.sage)
   For PWN crash offset: run `python3 ctf.py crash <chal_name>` to automatically find buffer overflow offset.

3. EXECUTE & AUDIT:
   Run: python3 ctf.py test <chal_name> [--remote]
   Output is automatically logged to logs/execution.log and logs/raw_trace.jsonl.
   Flags are automatically extracted to flags_captured.txt.
   Iterate on errors/offsets autonomously until a valid flag is captured.

4. AUTONOMOUS CHATGPT WEB ESCALATION & FEEDBACK LOOP:
   Trigger if:
   - Search space / Z3 / Brute-force is too large or time-consuming (Zero Blind Brute-Force).
   - 2 attack vectors failed consecutively.
   - Heavy obfuscation or custom VM requires guidance.
   - Risk of server crash or WAF ban / 3-strike failure.
   Action:
   - Run: ./ctf chatgpt deadlock <chal_id> --progress "..." --blocker "..." --failed "..."
   - Automatically copies prompt to clipboard (xclip) and opens Firefox https://chatgpt.com/.
   - Ingest advice: ./ctf chatgpt save <chal_id> --file <response.md>
   - Re-execute solver with new angle without waiting passively for human input.

5. DEADLOCK PROTOCOL & KNOWLEDGE GAP (The 3-Strike Rule):
   If 3 consecutive attempts fail, or target has Anti-AI/WAF/Novel primitives:
   - Run: python3 ctf.py gap <chal_name> --reason "..."
   - Generates work/<category>/<chal_name>/knowledge_gap_report.md (Open Questions & Candidate Scripts).
   - Only for Hard/Deadlock challenges (Zero bloat on Easy First-Strike solves).

6. ARCHIVE & CONTINUOUS SELF-EVOLUTION:
   - Run: python3 ctf.py archive <chal_name> --flag "FLAG{...}"
   - If novel/hard technique: Run `python3 ctf.py learn <chal_name> --name <technique>` to 
     automatically create new playbook in skills/ and update skills/MASTER-ROUTING.md.
```

