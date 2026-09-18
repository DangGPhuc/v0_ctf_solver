# IDA Pro MCP & IDAPython Reversing Knowledge Base

## 1. System Prompt & Strategy for IDA Pro Analysis
When analyzing a binary or solving a Reverse Engineering / CTF challenge using IDA Pro & MCP:

- Inspect the decompilation and add detailed comments with findings.
- Rename variables to sensible, descriptive names.
- Correct variable and argument types where necessary (especially pointer and array types).
- Change function names to be descriptive of their actual purpose.
- If more details are necessary, disassemble the function and examine low-level behaviors.
- **NEVER convert number bases yourself!** Use the `int_convert` MCP tool or Python scripts if needed.
- Do not attempt brute forcing manually; derive solutions purely from disassembly/decompilation and simple Python scripts.
- Organize findings clearly and output the final solution script (`solve.py`).

---

## 2. IDAPython Cheat Sheet & Module Router

Use modern `ida_*` modules. Avoid legacy `idc` module.

### Module Router Table
| Task | Module | Key Items |
|------|--------|-----------|
| Bytes/memory | `ida_bytes` | `get_bytes`, `patch_bytes`, `get_flags`, `create_*` |
| Functions | `ida_funcs` | `func_t`, `get_func`, `add_func`, `get_func_name` |
| Names | `ida_name` | `set_name`, `get_name`, `demangle_name` |
| Types | `ida_typeinf` | `tinfo_t`, `apply_tinfo`, `parse_decl` |
| Decompiler | `ida_hexrays` | `decompile`, `cfunc_t`, `lvar_t`, ctree visitor |
| Segments | `ida_segment` | `segment_t`, `getseg`, `add_segm` |
| Xrefs | `ida_xref` | `xrefblk_t`, `add_cref`, `add_dref` |
| Instructions | `ida_ua` | `insn_t`, `op_t`, `decode_insn` |
| Stack frames | `ida_frame` | `get_frame`, `define_stkvar` |
| Iteration | `idautils` | `Functions()`, `Heads()`, `XrefsTo()`, `Strings()` |
| Analysis | `ida_auto` | `auto_wait`, `plan_and_wait` |

### Core Code Snippets

#### Iterate Functions & Names
```python
import ida_funcs, idautils
for ea in idautils.Functions():
    name = ida_funcs.get_func_name(ea)
    func = ida_funcs.get_func(ea)
