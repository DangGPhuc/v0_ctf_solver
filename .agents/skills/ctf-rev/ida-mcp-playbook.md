# Autonomous IDA Pro MCP Reversing Playbook (skills/rev/ida-mcp-playbook.md)

## 1. IDA Pro MCP Autonomous Workflow

When working with binaries, use IDA Pro MCP tools directly in the loop:

```text
[1. Locate Entry & Functions]
  └─ mcp_ida-pro_list_functions
  └─ mcp_ida-pro_get_function_by_name("main")

[2. String & Cross-Reference Recon]
  └─ mcp_ida-pro_list_strings_filter(filter="flag|correct|wrong|key")
  └─ mcp_ida-pro_get_xrefs_to(address)

[3. Decompile & Extract Pseudo-C]
  └─ mcp_ida-pro_decompile_function(address)
  └─ Extract variable mappings & branch conditions

[4. Enrich IDB / Rename Variables]
  └─ mcp_ida-pro_rename_local_variable(func_addr, old_name, new_name)
  └─ mcp_ida-pro_rename_function(func_addr, new_name)
  └─ mcp_ida-pro_set_comment(address, comment)

[5. Direct Lift to Solver]
  └─ Copy extracted arithmetic/logic into templates/solve_rev.py (Z3)
```

---

## 2. Best Practices for AI Reverse Engineering
- Always inspect functions referenced by string cross-references (`"Enter password: "`, `"Correct!"`).
- Trace pointers back to stack arguments to determine exact flag length.
- Convert hex arrays in `.rodata` directly into Python byte arrays.
