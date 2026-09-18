# Deep Dive: Linux Kernel Exploitation & eBPF Verifier Bypasses

## 1. Modern Kernel Mitigation Matrix
- KASLR, SMEP, SMAP, KPTI (Page Table Isolation), Modprobe_path protection, Kernel Control Flow Integrity (kCFI).

---

## 2. Exploitation Primitives

### A. Dirty Cred (CVE-2022-2588 / CVE-2022-0847)
Overwriting credentials of current process by swapping `struct cred` in `current_task` or abusing `kmalloc-192` slab cache:
1. Free a non-privileged `struct cred`.
2. Allocate a privileged `struct cred` (e.g. via `setuid` or kernel daemon) to reclaim the same slab slot.
3. Obtain `root` capabilities without calling `commit_creds(prepare_kernel_cred(0))`.

### B. eBPF Verifier Pointer Tracking & Bounds Confusion
- Vulnerability: Integer truncation or sign-extension flaw in `check_alu_op()` inside `kernel/bpf/verifier.c`.
- Result: Verifier calculates `reg->umin_value = 0, reg->umax_value = 0` (thinks register is scalar 0), while at runtime register holds a non-zero value.
- Exploit:
  1. Add runtime value to a BPF map value pointer (`BPF_REG_PTR_TO_MAP_VALUE`).
  2. Achieve arbitrary kernel memory read/write.
  3. Overwrite `bpf_prog->bpf_func` or target task credentials.
