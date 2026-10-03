# T-02729: Threat Model Maintenance CLI Surface Documentation

- **Task**: `T-02729`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Threat Model Maintenance / CLI surface
- **Date**: 2026-10-03
- **Status**: PASSED

## 1. Documentation Scope
Synchronized and documented the Threat Model CLI surface in `docs/SPEC-THREAT-MODEL-CLI.md`:
1. Updated specification status to `IMPLEMENTED & VERIFIED`.
2. Documented full invariant set (`THREATCLI1` through `THREATCLI7`), adding `THREATCLI6` (Terminal Sanitization via `sanitize_terminal_output`) and `THREATCLI7` (Audit Target Provenance via `Some(&id)`).
3. Documented complete command syntax, argument flags, default locations (`docs/threat_model.json`), and exit code mappings (`0`, `1`, `2`, `3`).
4. Cross-referenced the test suite verification matrix in `code/aiosh-rust/aiosh-cli/src/main.rs`.
