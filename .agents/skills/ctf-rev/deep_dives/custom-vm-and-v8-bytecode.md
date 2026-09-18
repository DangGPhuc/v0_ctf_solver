# Deep Dive: Custom VM Bytecode Reversing & MBA Deobfuscation

## 1. Custom Virtual Machine Architecture in CTFs
VM-based challenges (e.g. Flare-On, DEF CON Quals) embed an interpreter loop:
```text
Bytecode Array ──► [ Fetch IP ] ──► [ Decode Opcode ] ──► [ Dispatch Table ] ──► [ Execute & Update Context ]
```

---

## 2. Reversing Strategy: Lift to Intermediate Representation (IR)

1. **Locate Virtual Registers & Context Struct**:
   - Trace memory accesses inside the main dispatch loop (e.g. `context->regs[opcode & 0x7]`).
2. **Build Disassembler / Lifter Script in Python**:
   ```python
   OPCODES = {
       0x01: ("ADD", 2),
       0x02: ("XOR", 2),
       0x03: ("LOAD_IMM", 2),
       0x04: ("JZ", 1),
       0x05: ("CMP", 2)
   }
   
   def disassemble_vm(bytecode: bytes):
       pc = 0
       while pc < len(bytecode):
           op = bytecode[pc]
           if op in OPCODES:
               name, arg_len = OPCODES[op]
               args = bytecode[pc+1 : pc+1+arg_len]
               print(f"0x{pc:04x}: {name:<10} {args.hex()}")
               pc += 1 + arg_len
           else:
               print(f"0x{pc:04x}: UNKNOWN_OP 0x{op:02x}")
               pc += 1
   ```

---

## 3. Mixed Boolean-Arithmetic (MBA) Deobfuscation
- Obfuscators replace simple equations like `x + y` with complex boolean expressions:
  $$x + y = (x \oplus y) + 2(x \land y) = (x \lor y) + (x \land y)$$
- **Solution**: Use `z3` simplification, or symbolic pattern equivalence tables via `msynth` / `syntia`.
