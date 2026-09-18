# Control Flow Deobfuscation & OLLVM (skills/rev/deobfuscation.md)

## 1. Recognizing Obfuscation Patterns

- **Control Flow Flattening (CFF)**: Functions are broken into basic blocks controlled by a single state variable in a giant `switch` statement inside a loop.
- **Bogus Control Flow (BCF)**: Opaque predicates (conditions that always evaluate to true/false, e.g. $y > 10 \text{ or } x(x+1) \% 2 == 0$) creating fake dead code branches.
- **Instruction Substitution & MBA**: Simple arithmetic $(x + y)$ transformed into complex boolean expressions $((x \oplus y) + 2 \cdot (x \land y))$.

---

## 2. De-flattening Strategies

1. **Symbolic Execution (Angr / D-Analyzer)**:
   - Identify the dispatcher block and state variable.
   - Execute each relevant basic block symbolically until the next state assignment.
   - Reconstruct the true Control Flow Graph (CFG) and patch binary jumps (`jmp target` instead of jumping back to the dispatcher).

2. **Mixed Boolean-Arithmetic (MBA) Simplification**:
   - Use `msynth` or Z3 simplification:
     ```python
     from z3 import *
     x, y = BitVecs('x y', 32)
     expr = (x ^ y) + 2 * (x & y)
     s = Solver()
     s.add(expr != x + y)
     assert s.check() == unsat # Proves equivalence to (x + y)
     ```
