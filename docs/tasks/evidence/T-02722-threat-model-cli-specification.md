# T-02722: Threat Model Maintenance CLI Surface Specification

- **Task**: `T-02722`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Threat Model Maintenance / CLI surface
- **Date**: 2026-10-03
- **Status**: PASSED

## 1. Specification Scope
Authored the formal specification for the Threat Model CLI surface in `docs/SPEC-THREAT-MODEL-CLI.md`:
1. Defined subcommands (`list`, `show`, `register`, `status`, `mitigate`, `assess`, `init`).
2. Defined invariants `THREATCLI1` through `THREATCLI5` (Audit completeness, path sanitization, standardized exit codes, zero secret disclosure, and atomic persistence).
3. Detailed command grammar, options, and defaults (`docs/threat_model.json`).
4. Standardized exit codes (`0`, `1`, `2`, `3`) mapped directly to operational outcomes.
