# Binary Exploitation (Pwn) Operational Workflow

1. Static Triage: Execute checksec, file, and seccomp-tools. Identify target architecture and active mitigations.
2. Vulnerability Discovery:
   - Stack: Buffer overflow (gets, read, scanf %s), format string (printf(buf)).
   - Heap: Use-After-Free, double free, heap overflow, off-by-one.
   - Logic: Integer overflow, type confusion, out-of-bounds index.
3. Primitive Construction:
   - Leak Phase: Extract libc base, binary base, canary, or stack address.
   - Control Phase: Construct ROP chain, format string write, or heap allocation override.
4. Local Verification: Test exploit script with pwntools against local binary or gdb.
5. Remote Exploitation: Deploy exploit against remote target service to capture flag.
