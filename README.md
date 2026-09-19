# ⚡ v0_ctf_solver — Autonomous CTF Lifecycle & Solving Orchestrator

An autonomous CTF competition orchestration framework and specialized exploitation suite for CTFd, GZCTF, and CyberHX/Supabase platforms. Built on an ephemeral runtime architecture, typed action execution boundaries, and on-demand external knowledge retrieval.

---

## 🏗️ Architecture Overview

```text
PlatformAdapter (CTFd / GZCTF / CyberHX)
      ↓ (Lazy Synchronization)
RuntimeManager (Ephemeral .runtime/<event>/)
      ↓
Strategic Advisor ←→ GitHubKnowledgeProvider (Private v0_ctf_knowledge via REST Contents API)
      ↓
ExecutionPlan (Typed ExecutionActions: run_solver, run_binary, tool allowlist)
      ↓
ContainerExecutor (Docker / Podman: --network none, --cap-drop ALL, isolated env)
      ↓
Evidence Evaluator (Flag candidate extraction & evidence verification)
      ↓
SubmitService (Instant submission & duplicate protection)
      ↓
KnowledgeOutbox (~/.local/state/v0_ctf_solver/knowledge-outbox/)
      ↓
Knowledge PR Publication (Automated branch creation & Pull Request via gh CLI)
```

### Core Architecture Principles

1. **Small Core, Zero Permanent Event Bloat**: Long-term repository state stores only framework code and operational agent skills (`.agents/skills/` < 500 KB).
2. **Ephemeral Runtime (`.runtime/`)**: Challenge workspaces, input attachments, and solver experiments are materialized on-demand under `.runtime/<event>/challenges/<id>/` and can be cleaned up immediately or post-event.
3. **External Remote Knowledge (`v0_ctf_knowledge`)**: Reusable technique cards and reference manuals live in the external `DangGPhuc/v0_ctf_knowledge` repository, accessed on-demand like a virtual drive using authenticated GitHub REST Contents API and local TTL caching.
4. **Strict Container Isolation**: Untrusted challenges execute inside rootless containers with dropped capabilities (`--cap-drop ALL`), `no-new-privileges`, isolated network profiles (`none` by default, `bridge` for remote targets), and stripped host secrets. Untrusted code is **never** silently re-executed on the host.
5. **Typed Execution Boundaries**: Models cannot supply arbitrary prose or shell commands. The executor only accepts structured `ExecutionAction` objects with path containment restricted to `work_dir` and tools restricted to an explicit allowlist.
6. **Closed Knowledge Feedback Loop**: Solved challenges stage candidate technique cards into `~/.local/state/v0_ctf_solver/knowledge-outbox/`. The `ctf knowledge publish` command validates, branches, rebuilds indexes, and opens a Pull Request on GitHub.

---

## 🧠 V3 Solver Intelligence (Evidence-Driven Hypothesis Loop)

The autonomous solver operates on an evidence-driven scientific cycle rather than unstructured trial-and-error:

```text
Fingerprint → Knowledge Context → Advisor Proposals (ExperimentCandidates)
    ↓
ExperimentPlanner (Lexicographic deterministic ranking: Executability > Hypothesis State > Retry Suppression > Evidence Novelty > Cost tie-breaker)
    ↓
Canonical Experiment Allocation (System-owned EXP-xxx under atomic .advisor/.experiments.lock)
    ↓
ActionPolicy & ExecutionRunner (Multi-action typed pipeline: run_solver, run_binary, analysis_tool)
    ↓
Execution Backend (ContainerExecutor / RestrictedLocalExecutor with bounded I/O)
    ↓
Deterministic EvidenceEvaluator (CONFIRMED / REJECTED / INCONCLUSIVE / FLAG_FOUND)
    ↓
HypothesisManager & SolverProgressTracker (State update, new evidence accounting, deterministic stagnation detection)
    ↓
Continue / Refine / Pivot
```

### Production Boundary Hardening
- **Atomic Concurrency-Safe Ledger**: `.advisor/.experiments.lock` ensures concurrent processes never receive duplicate canonical EXP IDs.
- **Idempotent Flag Submission**: Multi-process reservation via `.submitted_flags.lock` prevents race-condition double-submissions on CTF platforms; plaintext flags are not persisted.
- **Bounded Untrusted I/O**: `MAX_STDOUT_BYTES` (512 KB) and `DEFAULT_MAX_ATTACHMENT_BYTES` (50 MB) prevent host resource exhaustion. Stream truncation flags distinguish between complete and truncated output.
- **Injection-Safe Metadata**: All challenge metadata (names, connection info, hints) are serialized via structured JSON (`json.dumps()`), eliminating code-injection vectors in generated solver templates.

---

## 🚀 Quick Start

### 1. Requirements

- Python 3.10+
- Container engine: `docker` or `podman` (for sandboxed execution)
- GitHub CLI: `gh` (authenticated via `gh auth login`)
- Standard CTF tools: `pwntools`, `z3-solver`, `file`, `strings`, `checksec`, `readelf`

### 2. Installation

```bash
git clone https://github.com/DangGPhuc/v0_ctf_solver.git
cd v0_ctf_solver
python3 -m pip install -e .
```

### 3. Configuration

Configure target CTF credentials in `.env`:

```env
PLATFORM_URL="https://ctf.cyberhx.com"
SESSION_COOKIE="cf_clearance=..."
API_TOKEN="eyJ..."
FLAG_FORMAT="^FLAG\{.+\}$"
CTF_RUNTIME_DIR=".runtime"
KNOWLEDGE_ENABLED=true
KNOWLEDGE_REPO="DangGPhuc/v0_ctf_knowledge"
KNOWLEDGE_REF="main"
KNOWLEDGE_OFFLINE=false
```

### 4. Tournament Workflow (Anti-IDE & OpenCode Executors)

When participating in a new CTF competition:

1. **Create Tournament Folder**: Create a dedicated directory named after the tournament inside the repository:
   ```bash
   mkdir <tournament_name> && cd <tournament_name>
   ```
2. **Inject Credentials**: Pass the platform refresh token / session credentials to the Anti-IDE & OpenCode agents:
   ```bash
   ctf env set -u "https://ctf.target.com" -t "<REFRESH_TOKEN>" -c "session=..."
   ```
3. **Trigger Autonomous Solving Loop**:
   ```bash
   ctf auto --max-iter 10 --executor container
   ```
   Anti-IDE and OpenCode act as autonomous executors, pulling challenges, triaging primitives, generating typed experiments with Strategic Advisor, executing in isolated sandboxes, and submitting flags immediately.

4. **Post-Tournament Distillation & Zero-Bloat Teardown**:
   At the end of the competition, Anti-IDE triggers an automated distillation pass:
   - Sifts through discovery trees, extracting winning exploit paths, novel techniques, and anti-patterns.
   - Promotes reusable knowledge to the remote knowledge base (`DangGPhuc/v0_ctf_knowledge`) via Pull Request.
   - **Completely removes the tournament folder** (`rm -rf <tournament_name>`) and ephemeral caches, ensuring the repository remains 100% clean with **Zero Permanent Event Bloat**.

---


## 🛠️ CLI Reference

### Challenge Lifecycle & Autonomous Solving

```bash
# List unsolved challenges directly from CTF platform
ctf list

# Sync challenges into runtime metadata (.runtime/<event>/event.json)
ctf pull

# Run fully closed-loop autonomous solver cycle
ctf auto --max-iter 5 --executor auto

# Solve a specific challenge by ID
ctf solve 123 --max-iter 5 --executor container

# Submit a flag immediately
ctf submit 123 "FLAG{example_flag}"

# View runtime status
ctf status

# Clean up ephemeral runtime artifacts
ctf cleanup challenge 123
ctf cleanup event
ctf cleanup all
```

### Execution Modes & Security

The execution subsystem is governed by a canonical `ActionPolicy` and deterministic multi-action `ExecutionRunner`:
- `--executor auto` (Default): Uses `ContainerExecutor` (Docker/Podman). If no container engine is active, fails safely (fail-closed) to prevent untrusted code execution on host. Host fallback requires explicit `--allow-local-fallback`.
- `--executor container`: Strict container isolation with dropped capabilities (`--cap-drop ALL`), `no-new-privileges`, resource quotas (`--cpus=1`, `--memory=512m`), per-action timeouts, and `--network none` (isolated by default).
- `--executor restricted-local`: Hardened subprocess execution on host without `shell=True`, governed by `ActionPolicy`. Operands are strictly verified against `input/` (read-only) and `work/` (read-write) boundaries (external paths like `/etc/passwd` or `../../` are rejected), tool names are limited to `ALLOWED_ANALYSIS_TOOLS`, and host secrets are stripped. **NOTE: `restricted-local` is a restricted process execution boundary, NOT equivalent to a full OS/kernel sandbox.**
- `--executor unsafe-local`: Direct unconstrained host shell execution. Dangerous; strictly intended for controlled testing only.

### Remote Knowledge Management (`v0_ctf_knowledge`)

```bash
# Verify knowledge connectivity, authentication, and cache status
ctf knowledge doctor

# Synchronize latest index from remote GitHub repository
ctf knowledge sync

# Search technique cards by fingerprint query
ctf knowledge search "rop static elf" --category pwn

# Fetch a specific technique card
ctf knowledge fetch pwn.rop.static-elf-syscall-chain

# Offline search using local TTL cache
ctf knowledge search "rop static elf" --category pwn --offline

# Inspect staged candidate cards in outbox
ctf knowledge candidates

# Validate a candidate card for security and schema conformance
ctf knowledge validate ~/.local/state/v0_ctf_solver/knowledge-outbox/pwn.sample.yaml

# Publish candidate to v0_ctf_knowledge via Pull Request
ctf knowledge publish ~/.local/state/v0_ctf_solver/knowledge-outbox/pwn.sample.yaml
ctf knowledge publish --all-validated

# Clear local knowledge cache
ctf knowledge cache-clean
```

### Toolchains & MCP Integrations

```bash
# List available and installed toolchains
ctf tools list

# Check health and dependencies of a toolchain
ctf tools doctor ida-pro-mcp

# Install a toolchain from its manifest
ctf tools install ida-pro-mcp
```
