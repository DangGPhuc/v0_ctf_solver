---
name: ctf-audit
description: |
  CTF Source Code Auditing, Binary Static Triage, and Structured ReAct Reasoning Suite.
  Provides systematic Source-to-Sink analysis, C/binary vulnerability discovery patterns,
  and standardized multi-step reasoning protocols for CTF autonomous solving.
---

# CTF Auditing & Structured Reasoning Suite

## Core Capabilities
- **Source-to-Sink Dataflow Auditing**: Systematic tracking from untrusted sources to dangerous sinks across Python, Node.js, PHP, Java, and Go.
- **Binary Static Triage**: C library unsafe function detection, memory corruption primitives, checksec mitigation bypass matrix.
- **Autonomous ReAct Protocol**: Formal 5-step loop (Hypothesis $\to$ Static Proof $\to$ Minimal Probe $\to$ Weaponized Exploit $\to$ Flag Verification).

## Playbooks in this Module
- [whitebox_triage.md](v0_ctf_knowledge/references/audit/whitebox_triage.md): Source-to-Sink methodology, sink inventory, and fast regex triage.
- [binary_audit.md](v0_ctf_knowledge/references/audit/binary_audit.md): Unsafe C functions, checksec vs mitigations, static decompilation checklist.
- [structured_reasoning.md](v0_ctf_knowledge/references/audit/structured_reasoning.md): Standardized ReAct CTF problem solving and 3-strike deadlock break protocol.
