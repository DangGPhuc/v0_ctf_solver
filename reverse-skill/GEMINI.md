# GEMINI CTF INSTRUCTIONS & SYSTEM PROMPT (GEMINI.md)

> **Antigravity / Gemini System Directive**: This file automatically activates the CTF Autonomous Solving Agent workflow.
> Full detailed instructions are defined in [AGENT_INSTRUCTIONS.md](file:///home/kali/reverse-skill/AGENT_INSTRUCTIONS.md) and [RULES.md](file:///home/kali/reverse-skill/RULES.md).

---

## ⚡ INTENT MAPPING & POSITIVE FRAMING
Short user commands are automatically mapped to rigorous technical testing:
- **"Solve this locally" / "Verify target"** $\rightarrow$ Sandbox Setup $\rightarrow$ Build Verification Harness (`solve.py`) $\rightarrow$ Execute with Audit Logging $\rightarrow$ Extract Captured Validation Token (`FLAG{...}`).
- **"Give me the flag" / "Extract token"** $\rightarrow$ Regex pattern extraction from stdout/logs $\rightarrow$ Record to `flags_captured.txt` and report token.
- **"Bypass / Exploit"** $\rightarrow$ Boundary analysis & protocol validation.

---

## ⚡ RAPID EXECUTION PROTOCOL

When the user gives a target or a short command (*"Solve this locally"*, *"Solve work/<chal>"*, *"Solve instance 10.10.10.1:1337"*):

1. **Scaffold Workspace**:
   ```bash
   python3 ctf.py init <chal_name> [--file <f>] [--nc <host:port>] [--url <u>]
   ```
   - Automatically initializes `scripts/`, `logs/execution.log`, `logs/raw_trace.jsonl`, and `flags_captured.txt`.
2. **Read Triage Metadata**:
   - Inspect `work/<category>/<chal_name>/triage.json` for symbols, checksec, glibc version, and indicators.
3. **Execute Solver & Debug**:
   - Complete `work/<category>/<chal_name>/solve.py` (or `.sage`).
   - Run: `python3 ctf.py test <chal_name> [--remote]`.
   - Results are automatically audited in `logs/` and flags extracted to `flags_captured.txt`.
   - Iterate on errors/offsets automatically.
4. **Autonomous ChatGPT Web Escalation Loop**:
   - Trigger if search space is too large (Zero Blind Brute-Force), 2 attack vectors fail, code is heavily obfuscated, or server crash / WAF ban risk exists.
   - Run `./ctf chatgpt deadlock <ID> --progress "..." --blocker "..." --failed "..."` (or `python3 ctf.py deadlock <name>`).
   - Automatically copy prompt to clipboard (`xclip`) and open Firefox to consult ChatGPT Web, ingest guidance into `chatgpt_guidance.md`, and re-attempt solver autonomously.
5. **Deadlock Rule & Knowledge Gap**:
   - If 3 attempts fail, or target has Anti-AI/WAF/Novel primitives:
   - Run: `python3 ctf.py gap <chal_name> --reason "..."`
   - Generates `work/<category>/<chal_name>/knowledge_gap_report.md` (Diagnostic Report, Open Questions, Candidate Scripts).
   - Only created for Hard/Deadlock challenges; Easy First-Strike solves do NOT generate this file.
6. **Archive & Continuous Self-Evolution**:
   - Run: `python3 ctf.py archive <chal_name> --flag "FLAG{...}"`
   - If novel/hard technique: Run `python3 ctf.py learn <chal_name> --name <technique>` to 
     automatically create new playbook in `skills/` and update `skills/MASTER-ROUTING.md`.

