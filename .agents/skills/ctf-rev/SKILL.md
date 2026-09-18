---
name: ctf-rev
description: |
  CTF Reverse Engineering Playbook Suite.
  Covers Z3 SMT constraint solving, Angr symbolic execution, Custom VM reversing, OLLVM/Deobfuscation,
  IDA Pro MCP autonomous workflow, Anti-debugging bypasses, and specialized binaries (Go, Rust, Unity IL2CPP, WebAssembly, Android APK).
---

# CTF Reverse Engineering Suite

## Playbooks in this Module
- [z3-solver.md](v0_ctf_knowledge/references/rev/z3-solver.md): Translating decompiled C / bitwise constraints into Z3 SMT models.
- [angr-symbolic.md](v0_ctf_knowledge/references/rev/angr-symbolic.md): Path exploration, avoiding traps, hooking complex library calls.
- [vm-reversing.md](v0_ctf_knowledge/references/rev/vm-reversing.md): Custom bytecode architectures, opcode mapping, disassembler/emulator construction.
- [deobfuscation.md](v0_ctf_knowledge/references/rev/deobfuscation.md): OLLVM Control Flow Flattening recovery, Bogus Control Flow, Mixed Boolean-Arithmetic (MBA).
- [anti-analysis.md](v0_ctf_knowledge/references/rev/anti-analysis.md): Bypassing `ptrace`, `alarm`, `RDTSC`, TLS callbacks, self-modifying code.
- [ida-mcp-playbook.md](v0_ctf_knowledge/references/rev/ida-mcp-playbook.md): Autonomous reversing loop with IDA Pro MCP server.
- [specialized-rev.md](v0_ctf_knowledge/references/rev/specialized-rev.md): Go binary symbols recovery, Rust structures, Unity IL2CPP, WebAssembly (Wasm), Android APK/smali.
