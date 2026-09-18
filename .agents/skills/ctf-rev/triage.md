# Reverse Engineering Operational Triage

## 1. File Format & Architecture
- Determine ELF, PE, Mach-O, firmware blob, or bytecode (Java, .NET, Python, Erlang).
- Identify target architecture: x86-64, x86, ARM, MIPS, RISC-V.

## 2. Compiler & Runtime Signals
- C/C++: Standard libc/libstdc++ symbols.
- Go: Goroutines, runtime packages, pclntab structure.
- Rust: Demangled symbols, panic handling, core allocators.
- Packers/Protectors: UPX, VMProtect, Themida, custom entry point packers.

## 3. Anti-Analysis Detection
- Ptrace calls (PTRACE_TRACEME), IsDebuggerPresent, timing checks (RDTSC).
- Exception-based control flow (SIGTRAP, SEH).
