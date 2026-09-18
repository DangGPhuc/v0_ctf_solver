# CLAUDE CODE CTF INSTRUCTIONS (CLAUDE.md)

> **Claude Code System Directive**: This repository is configured as an Autonomous CTF AI Workspace.
> Full detailed instructions and rules are defined in [AGENT_INSTRUCTIONS.md](file:///home/kali/reverse-skill/AGENT_INSTRUCTIONS.md) and [RULES.md](file:///home/kali/reverse-skill/RULES.md).

---

## ⚡ CORE AUTONOMOUS WORKFLOW

1. **Initialize Workspace**:
   `python3 ctf.py init <chal_name> [--file <f>] [--nc <host:port>] [--url <u>]`
2. **Read Triage**:
   Read `work/<category>/<chal_name>/triage.json` for binary properties, symbols, and glibc versions.
3. **Develop & Test Solver**:
   Edit `work/<category>/<chal_name>/solve.py` and test via `python3 ctf.py test <chal_name> [--remote]`.
4. **Deadlock Protocol**:
   If 3 attempts fail, consult `skills/field-journal/` and output a full Diagnostic Report with mathematical models and candidate scripts.
5. **Archive Flag**:
   `python3 ctf.py archive <chal_name> --flag "FLAG{...}"`
