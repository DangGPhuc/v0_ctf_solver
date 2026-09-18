# Angr Symbolic Execution Playbook (skills/rev/angr-symbolic.md)

## 1. Fast Path Exploration Script

```python
import angr
import claripy

BINARY_PATH = './chal'
FLAG_LEN = 32

proj = angr.Project(BINARY_PATH, auto_load_libs=False)

# 1. Create symbolic variable for stdin input
flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(FLAG_LEN)]
flag_sym = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])

# 2. Initialize entry state with symbolic stdin
state = proj.factory.entry_state(
    args=[BINARY_PATH],
    stdin=flag_sym,
    add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY}
)

# 3. Add printable constraints
for c in flag_chars:
    state.solver.add(c >= 0x20)
    state.solver.add(c <= 0x7e)

# 4. Simulation Manager
simgr = proj.factory.simulation_manager(state)

# Replace with actual addresses from IDA
FIND_ADDR = 0x401234  # Address of "Correct!" / "Success"
AVOID_ADDR = 0x401250 # Address of "Wrong!" / "Fail"

simgr.explore(find=FIND_ADDR, avoid=AVOID_ADDR)

if simgr.found:
    found_state = simgr.found[0]
    solved_flag = found_state.solver.eval(flag_sym, cast_to=bytes)
    print(f"[+] Solved Flag: {solved_flag}")
else:
    print("[-] No path found.")
```
