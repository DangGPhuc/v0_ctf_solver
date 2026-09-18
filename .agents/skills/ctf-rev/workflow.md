# Reverse Engineering Operational Workflow

1. Static Extraction: Run strings, file, and readelf to extract string constants and exports.
2. Decompilation & CFG Analysis: Open in IDA Pro MCP or Ghidra. Identify main / start / handler logic.
3. Algorithm Identification: Locate verification loops (XOR, AES, custom cipher, CRC, Z3 constraint systems).
4. Constraint Solving / Emulation:
   - Linear / bitwise systems -> Model with Z3 solver.
   - Complex path exploration -> Angr symbolic execution.
   - Dynamic tracing -> Frida, QEMU, or GDB script.
5. Flag Reconstruction: Execute inverse transform or solve constraints to recover flag.
