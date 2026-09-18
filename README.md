# ⚡ v0_ctf_solver — Autonomous CTF Lifecycle & Solving Orchestrator

An autonomous, multi-agent CTF competition orchestration framework and specialized reverse engineering/exploitation suite for CTFd, GZCTF, and CyberHX/Supabase platforms.

---

## 🏗️ Architecture Overview

```text
v0_ctf_solver/
├── ctf                       # Unified CLI launcher entrypoint
├── ctf_suite/                # Core CTF Lifecycle Engine
│   ├── ctf_core/
│   │   ├── cli/              # Typer CLI subcommands (auto, pull, solve, advisor, instance, status)
│   │   ├── platforms/        # Platform Adapters (CyberHX, CTFd, GZCTF) with token refresh engine
│   │   ├── downloaders/      # Parallel resilient attachment downloaders
│   │   ├── services/         # Pull, Submit, Instance, Auto-pipeline services
│   │   ├── workspace/        # 4-tier Workspace Builder (challenge/, script/, solver/, writeup/)
│   │   ├── meta/             # Meta-layer (Dream-RSI discovery trees & offline replay)
│   │   └── prompts/          # State capsules & contract compilers
│   └── knowledge_base/       # Curated tactical cards & indexed patterns
├── reverse-skill/            # Complete CTF Exploitation Playbooks & Weaponized Toolchains
│   ├── skills/               # Domain-specific playbooks (Pwn, Rev, Crypto, Web, Forensics, Audit)
│   ├── toolchain/            # IDA Pro MCP server, wrappers, process management
│   └── templates/            # Standard solver templates (PWN ROP, Heap, Z3, Web async)
├── .agents/                  # Agent Skills & ReAct Dual-Agent Coordination Protocols
│   ├── ctf-anti-ide/         # Lifecycle & Closed-loop solving agent
│   ├── ctf-advisor/          # Strategic Advisor protocol (Anti-IDE ↔ ChatGPT Web)
│   ├── ctf-audit/            # Whitebox source auditing & ReAct reasoning
│   ├── ctf-pwn/              # Binary exploitation playbook
│   ├── ctf-rev/              # Reverse engineering playbook & IDA Pro workflow
│   ├── ctf-crypto/           # Cryptography attack suite
│   ├── ctf-web/              # Web application exploitation playbook
│   └── ctf-forensics/        # Network, Memory, Disk & Stego forensics
└── SAVED_NOTES.md            # Accumulated Writeups, Exploit Techniques & Verified Solutions
```

---

## 🚀 Quick Start

### 1. Requirements

- Python 3.10+
- `httpx`, `typer`, `rich`, `pydantic`, `pydantic-settings`
- Standard CTF tools (`pwntools`, `z3-solver`, `angr`, `tshark`, etc.)

### 2. Configure Environment

Copy `.env.example` to `.env`:

```bash
cp ctf_suite/.env.example .env
```

Set your CTF platform target and credentials in `.env`:
```env
PLATFORM_URL="https://ctf.cyberhx.com"
SESSION_COOKIE="cf_clearance=..."
API_TOKEN="eyJ..."
REFRESH_TOKEN="..."
FLAG_FORMAT="^Null0rigin\{.+\}$"
```

### 3. Usage Commands

```bash
# View dashboard and unsolved challenge tree
./ctf status

# Pull all challenges and build 4-tier workspaces
./ctf pull -o CTF_Workspace

# Run complete closed-loop autonomous solver pipeline
./ctf auto -o CTF_Workspace

# Submit a flag right away
./ctf submit --id <CHALLENGE_ID> -f "FLAG{...}"

# Manage dynamic Docker containers
./ctf instance start <CHALLENGE_ID>
./ctf instance stop <CHALLENGE_ID>
```

---

## 🔒 Security & Safe Practice

- Secret configurations (`.env`) and tournament tokens are strictly ignored by `.gitignore`.
- Raw challenge binary dumps and massive attachments are cached locally in ephemeral workspaces without polluting git history.
