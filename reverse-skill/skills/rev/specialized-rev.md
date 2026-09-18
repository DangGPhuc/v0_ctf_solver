# Specialized Binaries Reversing (skills/rev/specialized-rev.md)

## 1. Golang Binaries (Stripped)
- **Tool**: `go-strip` recovery, `IDAGolangHelper`, or `goret` script.
- **Key Concepts**:
  - Functions take pointers via stack or registers (`rax`, `rbx`, `rcx` in Go >= 1.17).
  - Strings are `(pointer, length)` tuples (no null-terminator).
  - Search `pclntab` or `gopclntab` to restore original function names.

---

## 2. Rust Binaries
- **Key Concepts**:
  - Heavy inlining and mangled symbol names (`_ZN...`). Use `rustfilt` to demangle.
  - Rust slices: `(pointer, length)` or `(pointer, capacity, length)`.
  - Look for `match` dispatch tables and `Result`/`Option` unwrap panics.

---

## 3. Unity IL2CPP (.so / .dll)
- **Tools**: `Il2CppDumper`, `Cpp2IL`.
- **Methodology**:
  1. Locate `libil2cpp.so` (or `GameAssembly.dll`) and `global-metadata.dat`.
  2. Run `Il2CppDumper.exe <libil2cpp.so> <global-metadata.dat> <output_dir>`.
  3. Load `script.py` in IDA Pro to restore all class names, methods, and field offsets.

---

## 4. WebAssembly (.wasm)
- **Tools**: `wasm2c`, `wasm-decompile`, `wabt`.
- **Methodology**:
  - Run `wasm2c challenge.wasm -o challenge.c` to compile Wasm into readable C code.
  - Analyze memory arrays `wasm_rt_allocate_memory` and exports.

---

## 5. Android APK & Smali
- **Tools**: `jadx-gui`, `apktool`, `frida`.
- **Methodology**:
  - `jadx challenge.apk -d src/` for Java decompilation.
  - If Native (`.so`), analyze with IDA Pro MCP via JNI methods (`Java_com_example_MainActivity_validate`).
