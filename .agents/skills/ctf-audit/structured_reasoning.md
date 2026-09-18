# Structured Reasoning & ReAct Protocol for CTF (skills/audit/structured_reasoning.md)

## 1. The Autonomous CTF ReAct Loop

To eliminate hallucination, premature exploit attempts, and cyclic failures, all solving actions MUST follow the 5-step ReAct framework:

```text
┌──────────────────────────────────────────────────────────────────────────┐
│ 1. HYPOTHESIS: State exact suspected vulnerability & intended primitive. │
│ 2. EVIDENCE: Provide concrete proof from source code / disassembly.      │
│ 3. MINIMAL PROBE: Send smallest non-destructive probe to confirm state.  │
│ 4. WEAPONIZATION: Construct full exploit chain (ROP / Gadget / Payload). │
│ 5. VERIFICATION: Verify flag capture pattern (FLAG{...} or regex).      │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Step-by-Step Reasoning Framework

### Step 1: Hypothesis Formulation
- **Do NOT guess blindly.**
- Define: "Target binary contains an off-by-one in `vuln()` at offset 0x401122 leading to 8-byte stack overflow, allowing RBP overwrite."

### Step 2: Static & Dynamic Evidence
- Extract exact addresses, offsets, or code lines.
- Example:
  - Binary: `read(0, buf, 0x80)` into `char buf[0x70]`. Offset to RIP is `0x78`.
  - Web: `pickle.loads(base64.b64decode(user_input))` without signature verification.

### Step 3: Minimal Verification Probe
- Before writing a 100-line exploit, test connectivity and trigger conditions with minimal input:
  - PWN: Test cyclic pattern to verify crash offset (`python3 ctf.py crash <chal>`).
  - Web: Send canary test payload (e.g. `{{7*7}}` -> `49` for SSTI, or test canary header).

### Step 4: Weaponized Exploit Construction
- Use standard modular solvers (`templates/solve_pwn.py`, `templates/solve_web.py`).
- Implement robust I/O handling: `recvuntil()`, status code checks, timeout guards.

### Step 5: Flag Validation & Audit
- Extract validation token matching `FLAG{...}` or custom challenge format.
- Output captured flag to `flags_captured.txt` and archive via `python3 ctf.py archive <chal> --flag "..."`.

---

## 3. The 3-Strike Deadlock Protocol

When 3 consecutive test attempts fail:
1. **STOP executing random variations.**
2. Check assumptions against the Diagnostic Matrix:
   - *Is the architecture/endianness correct?*
   - *Is ASLR/PIE shifting addresses?*
   - *Is a 16-byte stack alignment missing in the ROP chain?*
   - *Is the payload getting truncated by null bytes / newlines (`scanf`, `strcpy`)?*
   - *Is the web session / CSRF token expiring?*
3. Formulate a new hypothesis based on failure logs (`logs/execution.log`).
