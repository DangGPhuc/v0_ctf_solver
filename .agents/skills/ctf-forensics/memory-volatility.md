# Memory Forensics with Volatility 3 (skills/forensics/memory-volatility.md)

## 1. Volatility 3 Core Command Matrix

### 1.1 Process & Injection Analysis
```bash
# List all processes
vol -f mem.raw windows.pslist
vol -f mem.raw windows.pstree

# Scan for hidden/unlinked processes
vol -f mem.raw windows.psscan

# Detect injected code & shellcode
vol -f mem.raw windows.malfind --dump
```

### 1.2 Network Connections
```bash
vol -f mem.raw windows.netscan
```

### 1.3 File Extraction & Command Line History
```bash
# Extract executed command lines
vol -f mem.raw windows.cmdline

# Scan and dump files from memory
vol -f mem.raw windows.filescan | grep -i "flag"
vol -f mem.raw -o ./dump windows.dumpfiles --virtaddr <VirtualAddress>
```

### 1.4 Password Hashes & LSA Secrets
```bash
vol -f mem.raw windows.hashdump
vol -f mem.raw windows.lsadump
```
