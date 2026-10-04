# T-02823: Compliance Mapping CLI Surface Scaffold

- **Task**: `T-02823`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / CLI surface
- **Date**: 2026-10-04
- **Status**: PASSED

## 1. Scaffold Scope
1. **CLI Dispatch Integration (`main.rs`)**:
   - Added `Some("compliance") | Some("comp") => cmd_compliance(&args[1..]),` to top-level `fn main()` dispatcher.
   - Updated `--help` synopsis with `aiosh compliance <list|show|register|status|assess|check-pep|init>`.
2. **Subcommand Handler Scaffold (`fn cmd_compliance`)**:
   - Routed execution across subcommands: `list`, `show`, `register`, `status`, `assess`, `check-pep`, `init`, `--help`, and unknown commands.
   - Connected `classify_and_emit` to guarantee an audit row for every invocation (`COMPLYCLI1`).
   - Integrated `--path` parameter with early validation via `ComplianceService::validate_path` (`COMPLYCLI2`).
   - Wired `--json` mode formatting and fail-closed exit codes.
