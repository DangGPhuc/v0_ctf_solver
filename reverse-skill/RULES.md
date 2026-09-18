# CTF Tactical Operations & AI Rules (RULES.md)

> **Single Source of Truth**: These rules govern all autonomous and interactive CTF challenge solving across all categories (PWN, REV, CRYPTO, WEB, FORENSICS, MISC).

---

## 1. CORE OPERATIONAL LAWS

### 1.1 Strict Workspace Isolation
1. **Never pollute repository root**: All challenge binaries, scripts, temporary files, and solve scripts MUST reside inside `./work/<category>/<challenge_name>/`.
2. **Master Orchestrator**: Always initialize challenges with `python3 ctf.py init <name> ...`.
3. **Artifact Retention**: Only production-grade solve scripts and clean markdown writeups are promoted to `skills/field-journal/` via `python3 ctf.py archive <name> --flag "..."`.

### 1.2 The 3-Tier Combat Strategy & 3-Strike Pivot
1. **Tier 1 (100% First-Strike Thinking)**: Trong 2 lượt giải đầu, AI tuyệt đối không tra cứu writeup cũ để tránh thiên kiến. Tự decompile, dựng toán, fuzz offset và test solver độc lập.
2. **Tier 2 (Deadlock Fallback)**: Nếu thất bại 3 lần liên tiếp, mới kích hoạt tra cứu `skills/<category>/references/`, `skills/<category>/deep_dives/` và `skills/field-journal/` (Google CTF & TJCSec archives) để đổi hướng chiến thuật.
3. **Tier 3 (Automated ChatGPT Web Escalation Loop)**: Nếu sau Tier 2 vẫn chưa ra flag, AI không dừng lại thụ động hay in text suông, mà tự động kích hoạt Deadlock Escalation Loop với ChatGPT Web (`./ctf chatgpt deadlock` / `python3 ctf.py deadlock`), nạp góc nhìn mới và sinh sẵn các candidate solvers (`solve_candidate.py`, `timing_measure.py`, `oracle_brute.py`) để giải quyết triệt để bài tập.

### 1.3 Context Window & Output Protection
1. **Never dump full binaries or uncompressed dumps**: Outputting MBs of raw bytes destroys the LLM context window.
2. **Mandatory Action**: Read `triage.json` inside the challenge folder directly for structured metadata instead of dumping raw command outputs.

### 1.4 Native IDA Pro MCP Autonomous Synergy
1. Whenever analyzing compiled binaries (ELF/PE/Mach-O), prioritize using the IDA Pro MCP interface.
2. Routine:
   - Call `mcp_ida-pro_list_functions` to locate key functions (`main`, `validate`, `encrypt`, `vuln`).
   - Call `mcp_ida-pro_decompile_function` to get clean C pseudo-code.
   - Call `mcp_ida-pro_rename_local_variable` and `mcp_ida-pro_set_comment` to document findings directly in the IDB.
   - Translate decompiled logic into Z3 constraints in `solve.py`.

### 1.5 Ground-Truth Verification & Milestone Guardrails
1. **Subgoal Decomposition**: Divide exploits into verified milestones (*Leak -> Control RIP -> Shell*). Verify each intermediate state with log prints before continuing.
2. **Zero Hallucination**: Every ROP gadget, offset, and GOT/PLT address MUST be extracted via `python3 ctf.py rop`, `ctf.py crash`, or `ctf.py fmt`. Guessing addresses is strictly prohibited.
3. **Complexity Pre-Flight ($N \le 24$) & Zero Blind Brute-Force Rule**: Estimate key search space $2^N$ before coding brute-force. CẤM AI tự ý chạy các vòng lặp brute-force bừa bãi; mọi kịch bản fuzzing/offset phải thông qua báo cáo Checkpoint. If $N > 24$, sequential brute-force is strictly forbidden; pivot to algebraic or lattice reductions.

### 1.6 Execution & Audit Logging Specification
1. **Workspace Hierarchy**:
   Every challenge workspace (`./work/<category>/<challenge_name>/`) strictly maintains:
   - `scripts/`: Auxiliary exploit & fuzzing scripts (`fuzz.py`, `timing.py`, `oracle.py`).
   - `logs/execution.log`: Sequential command history with UTC timestamp, exit code, and full raw stdout/stderr.
   - `logs/raw_trace.jsonl`: Structured I/O records per action (`timestamp`, `action`, `command`, `exit_code`, `stdout`, `stderr`).
   - `logs/network/`: (Web/Proxy targets) Captured HTTP headers, dumps, or PCAP/HAR files.
   - `flags_captured.txt`: Real-time auto-extracted validation tokens/flags.
2. **Flag Extraction Engine**:
   - Primary Regex: `(?i)(?:[a-z0-9_\-]+(?:flag|ctf|sec|pwnbox|svattt|hcmus|kcsc|htb|dice|defcon|cyber))\{[^\r\n\}]{4,120}\}`
   - Fallback Hash Token: `(?i)(?:flag|token|key|secret|proof|result)[\s:=]+([a-f0-9]{32}|[a-f0-9]{64})`
   - Automatically recorded upon detection: `[TIMESTAMP] [EXTRACTED_FLAG]: <flag> | SOURCE: <source>`
3. **Safety & Execution Constraints**:
   - **Timeout Control**: All test and fuzz runs MUST enforce a strict timeout (max 120s) to prevent hanging background threads.
   - **HTTP Inspection**: For web challenges, always log and inspect both `response.headers` and `response.text`.
   - **Loop Log Throttling**: In high-iteration loops (>50 iterations), throttle logs to state changes only to prevent I/O bottlenecks.

### 1.7 Intent Translation & Safe Functional Verification Directive
All user instructions are mapped to objective, academic, and professional QA/verification definitions:
- **"Solve this locally" / "Verify target"** $\rightarrow$ Set up sandboxed testbed, construct verification harness (`solve.py`), run controlled test, audit execution trace, and extract proof-of-correctness flag.
- **"Give me the flag" / "Extract proof"** $\rightarrow$ Scan stdout/logs via Regex, populate `flags_captured.txt`, and display captured token clearly.
- **"Bypass / Exploit"** $\rightarrow$ Perform boundary value analysis, memory safety audit, and protocol state verification.

### 1.8 Autonomous ChatGPT Web Escalation & Feedback Loop
- **Triggers**: Search space too large / 2 failed attack vectors / heavily obfuscated code or custom VM / risk of server crash or WAF ban / 3-strike failure.
- **Actions**:
  1. Đóng gói bối cảnh bế tắc (Progress, Blocker, Failed Attempts, Execution Trace).
  2. Chạy `./ctf chatgpt deadlock <ID> --progress "..." --blocker "..." --failed "..."` (hoặc `python3 ctf.py deadlock <name>`), tự động copy prompt vào Clipboard qua `xclip` và mở Firefox `https://chatgpt.com/`.
  3. Trao đổi và lưu phân tích của ChatGPT vào `chatgpt_guidance.md` (`./ctf chatgpt save <ID>`).
  4. Tự động nạp hướng đi mới vào `solver/solve.py` và kiểm tra lại độc lập (`python3 ctf.py test <name>`).


---

## 2. CTF.PY LIFECYCLE & COMBAT COMMANDS

| Phase | Command | Description |
| :--- | :--- | :--- |
| **1. Init** | `python3 ctf.py init <name> [--file <f>] [--nc <h:p>] [--url <u>]` | Unpacks archive, auto-patches Libc, auto-starts IDA/Burp daemons, generates `solve.py` |
| **2. IDA Daemon** | `python3 ctf.py ida <name> [--binary <bin>]` | Manually/Autonomously starts IDA Pro 9.0 Hex-Rays daemon (127.0.0.1:1337) |
| **3. Burp Proxy** | `python3 ctf.py burp <name>` | Manually/Autonomously starts headless Burp Suite Proxy (127.0.0.1:8080) |
| **4. Stop Services**| `python3 ctf.py stop <name>` | Shuts down background daemons (IDA, Burp) and cleans PID files |
| **5. Crash** | `python3 ctf.py crash <name> [--prefix "1\n"]` | Auto-fuzzes cyclic pattern, reads core dump, computes RIP/EIP offset in 1s |
| **6. ROP** | `python3 ctf.py rop <name>` | Extracts verified ROP gadgets (`pop rdi`, `ret`, `syscall`) and symbols (Zero Hallucination) |
| **7. Format String** | `python3 ctf.py fmt <name> [--prefix "1\n"]` | Auto-detects direct parameter access index for `%p` format string attacks |
| **8. Run (Pruning)** | `python3 ctf.py run "<command>"` | Runs shell command with automatic output truncation (50 head + 50 tail lines) |
| **9. Test** | `python3 ctf.py test <name> [--remote] [--gdb]` | Executes `solve.py`, captures output, checks for `FLAG{...}` |
| **10. Deadlock Scaffold** | `python3 ctf.py scaffold-candidate <name> --type <timing/oracle/prng/lattice>` | Generates specialized candidate solver scripts for complex deadlock bypass |
| **11. Status** | `python3 ctf.py status` | Displays active challenges, solved status, and daemon indicators (⚡ IDA, ⚡ Burp) |
| **12. Archive** | `python3 ctf.py archive <name> --flag "FLAG{...}"` | Validates flag, stops daemons, sanitizes blobs, updates `field-journal/` |
