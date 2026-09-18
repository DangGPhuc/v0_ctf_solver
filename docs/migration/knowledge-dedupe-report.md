# Knowledge & Skills Deduplication Report

## Overview

This report documents the deduplication of skills and references between `v0_ctf_solver` and the external `DangGPhuc/v0_ctf_knowledge` repository.

## 1. Skill Reference Deduplication in `.agents/skills`

Prior to refactoring, every category skill in `.agents/skills/ctf-<category>/` maintained a redundant `references/` subdirectory containing exact bit-for-bit duplicates of the category root playbooks.

- **Deduplicated Subtrees Removed from Core**:
  - `.agents/skills/ctf-crypto/references/` (16 duplicate files removed)
  - `.agents/skills/ctf-pwn/references/` (18 duplicate files removed)
  - `.agents/skills/ctf-misc/references/` (15 duplicate files removed)
  - `.agents/skills/ctf-rev/references/` (22 duplicate files removed)
  - `.agents/skills/ctf-web/references/` (22 duplicate files removed)
  - `.agents/skills/ctf-forensics/references/` (17 duplicate files removed)
- **External Destination**:
  All unique encyclopedic reference documents have been migrated to:
  `DangGPhuc/v0_ctf_knowledge` under `references/{pwn,rev,web,crypto,forensics,misc,general}/`.
- **Remaining Duplicate Groups in `.agents/skills/`**: **0**

## 2. Dismantling of `reverse-skill/`

The monolithic `reverse-skill/` directory was removed from the core solver repository:
- **Solver Templates**: Migrated to canonical runtime tooling at `ctf_suite/ctf_core/execution/templates/`.
- **Field Journal**: Migrated to `DangGPhuc/v0_ctf_knowledge/writeups/field-journal/`.
- **Duplicate Skills**: `reverse-skill/skills/*` was 100% duplicate of `.agents/skills/*`; deleted.
- **Vendored Toolchain**: `reverse-skill/toolchain/ida-pro-mcp` (6.4 MB) replaced with lightweight manifest and on-demand installer `ctf_suite/ctf_core/tools/manifests/ida-pro-mcp.yaml`.
- **Attribution**: Upstream MIT license preserved in `THIRD_PARTY_NOTICES.md`.
