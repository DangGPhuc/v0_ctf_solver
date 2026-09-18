# Anti-Analysis & Anti-Debugging (skills/rev/anti-analysis.md)

## 1. Common Anti-Debugging Techniques in CTF

### 1.1 Linux Targets
1. **`ptrace(PTRACE_TRACEME, 0, 1, 0)`**:
   - Returns `-1` if already under GDB.
   - **Patch**: NOP out `ptrace` call or patch return value in GDB (`catch syscall ptrace`, `set $rax = 0`).
2. **`alarm(seconds)` / `SIGALRM`**:
   - Kills debugged process after a timeout.
   - **Patch**: `handle SIGALRM ignore` in GDB or NOP out `alarm()`.
3. **Timing Checks (`RDTSC` / `clock_gettime`)**:
   - Measures CPU cycles between two instructions to detect single-stepping.
   - **Patch**: NOP `rdtsc` or patch `cmp` condition.
4. **`/proc/self/status` `TracerPid`**:
   - Checks if `TracerPid != 0`.
   - **Patch**: LD_PRELOAD `open`/`read` hook or binary patch.

### 1.2 Windows Targets
1. **`IsDebuggerPresent()` / PEB `BeingDebugged` flag**:
   - `mov eax, fs:[30h]; movzx eax, byte ptr [eax+2]`.
2. **`CheckRemoteDebuggerPresent()`**.
3. **TLS Callbacks**:
   - Executed before `main()` / entry point. Always check TLS directory in IDA/PE-bear.
