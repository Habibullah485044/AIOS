# T-02723: Threat Model Maintenance CLI Surface Scaffold

- **Task**: `T-02723`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Threat Model Maintenance / CLI surface
- **Date**: 2026-10-03
- **Status**: PASSED

## 1. Scaffold Scope
1. **CLI Dispatch Integration (`main.rs`)**:
   - Added `Some("threat") | Some("threats") | Some("tm") => cmd_threat(&args[1..]),` to top-level `fn main()` dispatcher.
   - Updated `--help` synopsis with `aiosh threat <list|show|register|status|mitigate|assess|init>`.
2. **Subcommand Handler Scaffold (`fn cmd_threat`)**:
   - Routed execution across subcommands: `list`, `show`, `register`, `status`, `mitigate`, `assess`, `init`, `--help`, and unknown commands.
   - Connected `classify_and_emit` to guarantee an audit row for every invocation.
   - Integrated `--path` parameter with fallback to canonical `DEFAULT_THREAT_MODEL_PATH`.
   - Wired `--json` mode formatting and fail-closed exit codes.
