# CTF AI Workspace & Master Orchestrator

A high-performance, CTF-centric AI workspace and toolchain suite designed for competitive cybersecurity competitions (DEF CON CTF, Google CTF, HITCON, PlaidCTF, DiceCTF, HackTheBox, etc.).

---

## 📁 Repository Architecture

```text
.
├── ctf.py                           # Master Orchestrator CLI (init, test, status, archive)
├── .cursorrules                     # Global AI System Prompt & Router configuration
├── AGENT_ROUTER.md                  # Comprehensive AI decision tree & triage matrix
├── RULES.md                         # Core Operational Rules (3-Strike Pivot, Workspace Isolation)
├── skills/
│   ├── MASTER-ROUTING.md            # Rapid triage table (Signatures -> Playbooks & Templates)
│   ├── routing.md                   # Deep technical routing by challenge characteristic
│   ├── field-journal/               # Writeups archive and self-learning experience bank
│   │   ├── _index.md
│   │   ├── _template.md
│   │   └── <YYYY-MM-DD>_<chal>.md
│   ├── pwn/                         # Playbooks: Heap (Glibc 2.23-2.39), ROP, Format String, Kernel, SROP
│   ├── rev/                         # Playbooks: Z3 solver, Angr, VM reversing, OLLVM, IDA Pro MCP
│   ├── crypto/                      # Playbooks: Lattice (LLL/HNP/CVP), RSA, ECC, PRNG (MT19937), AES
│   ├── web/                         # Playbooks: Async Blind SQLi/SSTI, Prototype Pollution, JWT, Deserialization
│   ├── forensics/                   # Playbooks: PCAP stream analysis, Volatility 3, Stego, PNG repair
│   └── misc/                        # Playbooks: PyJail escapes, RBash bypasses, Esoteric, AI CTF
├── templates/                       # Standardized boilerplate solvers
│   ├── solve_pwn.py                 # Pwntools scaffold (LOCAL / REMOTE / GDB debug)
│   ├── solve_rev.py                 # Z3 BitVector model & Angr finder templates
│   ├── solve_crypto.sage            # SageMath matrix, LLL & discrete math scaffolding
│   ├── solve_web.py                 # High-speed async requests & binary search blind extractor
│   └── solve_misc.py                # PyJail escape tester & remote socket solver
├── toolchain/
│   ├── bootstrap.py                 # Environment diagnostic & auto-dependency installer
│   └── triage.py                    # Instant automated challenge analyzer & router
└── work/                            # Isolated workspaces by category (.gitkeep)
    ├── pwn/
    ├── rev/
    ├── crypto/
    ├── web/
    ├── forensics/
    └── misc/
```

---

## ⚡ Master CTF Workflow (`ctf.py`)

### 1. Initialize Challenge Workspace
```bash
# From an archive containing binary + libc + ld:
python3 ctf.py init my_pwn_chal --file ./dist.zip --nc "10.10.10.1:1337"

# From a web URL:
python3 ctf.py init my_web_chal --url "http://target.ctf:8080"
```
**Auto-Actions**:
- Unpacks archives.
- Classifies files (binary, libc, loader, dockerfile, source).
- Automatically patches binary with `patchelf` to bind local libc & ld.
- Interpolates variables into `solve.py`.
- Generates structured metadata in `triage.json` (symbols, checksec, glibc version, decompilation preview).

### 2. Check Challenge Status
```bash
python3 ctf.py status
```

### 3. Test Exploit Execution
```bash
# Test solver locally
python3 ctf.py test my_pwn_chal

# Test solver against remote CTF server
python3 ctf.py test my_pwn_chal --remote
```

### 4. Archive Flag & Sanitize Blobs
```bash
python3 ctf.py archive my_pwn_chal --flag "FLAG{pwn_tcache_poison_easy}"
```
**Auto-Actions**:
- Validates flag format.
- Removes heavy binary artifacts & core dumps to keep Git repository lightweight.
- Auto-generates markdown writeup with embedded solve script in `skills/field-journal/<YYYY-MM-DD>_<name>.md`.
- Appends entry to `skills/field-journal/_index.md`.
