# T-02829: Compliance Mapping CLI Surface Documentation

- **Task**: `T-02829`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / CLI surface
- **Date**: 2026-10-04
- **Status**: PASSED

## 1. Documentation Updates
- Updated [docs/SPEC-COMPLIANCE-CLI.md](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/SPEC-COMPLIANCE-CLI.md) with comprehensive operator and agent documentation:
  - Full CLI grammar and syntax reference for all subcommands (`list`, `show`, `register`, `status`, `assess`, `check-pep`, `init`).
  - Copy-pasteable shell examples for store initialization, mapping queries, control registration, compliance posture assessment, and PEP gate verification.
  - Transparent disclosure of operational constraints: 1 MiB store file size cap, framework vocabulary restrictions, and local SQLite audit ring dependencies.
  - Traceability links to evidence artifacts across the sub-epic (`T-02821` through `T-02828`).

## 2. Invariants & Usage Summary
- All invocations follow deterministic exit codes: 0 for success, 1 for logical domain rejection, 2 for syntax/argument/path validation failure, 3 for storage I/O issues.
- Structured JSON envelope format supported across all commands using `--json`.
- Strict terminal sanitization prevents control character injection in interactive environments.
