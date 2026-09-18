# VM Reversing & Bytecode Emulation (skills/rev/vm-reversing.md)

## 1. Structure of a CTF VM Challenge

A typical custom VM in CTF consists of:
1. **Instruction Pointer (`pc` / `ip`)**.
2. **Virtual Registers Array (`reg[8]` / `r0..r7`)**.
3. **Virtual Stack / Memory (`stack[1024]`, `memory[4096]`)**.
4. **Bytecode Array (`bytecode[]`)**.
5. **Main Dispatch Loop**:
   ```c
   while (running) {
       uint8_t opcode = bytecode[pc++];
       switch (opcode) {
           case 0x01: reg[r_dst] = reg[r_src1] + reg[r_src2]; break;
           case 0x02: reg[r_dst] = reg[r_src1] ^ reg[r_src2]; break;
           case 0x03: reg[r_dst] = memory[reg[r_addr]]; break;
           case 0x04: if (reg[r_dst] == 0) pc = target; break;
       }
   }
   ```

---

## 2. Reverse Engineering Methodology

1. **Extract the Bytecode & Opcode Table**:
   - Extract raw bytecode from `.rodata` or global arrays.
   - Map every `case 0x..` in IDA Pro to human-readable assembly mnemonics (`ADD`, `XOR`, `MOV`, `CMP`, `JMP`, `JZ`).

2. **Write a Custom Disassembler**:
   ```python
   def disassemble(bytecode):
       pc = 0
       while pc < len(bytecode):
           op = bytecode[pc]
           if op == 0x01:
               print(f"{pc:04x}: ADD r{bytecode[pc+1]}, r{bytecode[pc+2]}")
               pc += 3
           elif op == 0x02:
               print(f"{pc:04x}: XOR r{bytecode[pc+1]}, 0x{bytecode[pc+2]:02x}")
               pc += 3
           # ...
   ```

3. **Symbolic Execution / SMT Lifting**:
   - Instead of manually tracing thousands of VM instructions, lift the disassembler into Z3 BitVectors to solve the input directly.
