# Scaffold Evidence: Incident Response Runbooks & RustSec CLI Surface (T-02985)

- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Incident Response Runbooks & RustSec Tooling / CLI surface
- **Task ID**: `T-02985`
- **Specification Document**: `docs/SPEC-INCIDENT-RUNBOOK-CLI.md`

## 1. Scaffold Implementations
1. **RustSec Security Tooling Substrate (`aiosh-core/src/sec_tools.rs`)**:
   - Created `sec_tools` module in `code/aiosh-rust/aiosh-core/src/sec_tools.rs`.
   - Defined data models: `ScanNetResult`, `FileMatch`, `ScanFilesResult`, `WebEndpointMatch`, `ScanWebResult`.
   - Defined core function signatures and validation bounds:
     - `validate_scan_target(target)`
     - `scan_net(target, ports, timeout_s, grant_token)`
     - `scan_files(target_dir, pattern, max_depth, timeout_s, grant_token)`
     - `scan_web(base_url, wordlist, depth, timeout_s, grant_token)`
   - Exported module in `code/aiosh-rust/aiosh-core/src/lib.rs`.

2. **Shell CLI Routing & Subcommands (`aiosh-cli/src/main.rs`)**:
   - Integrated dispatch branches in `main()` for:
     - `aiosh runbook` (alias: `aiosh rb`)
     - `aiosh scan` (with subcommands `net`, `files`, `web`)
   - Implemented `cmd_runbook` handling `list`, `show`, `init`, `start`, `step`, `confirm`, `abort`, `status`.
   - Implemented `cmd_scan` handling `net`, `files`, `web`.
   - Wired `classify_and_emit` to guarantee Proof-of-Receipt audit logging for every command execution.

## 2. Test Verification
- Ran `cargo test -p aiosh-core --test test_sec_tools_scaffold`: 2/2 tests passed (`test_sec_tools_scaffold_target_validation`, `test_sec_tools_scaffold_signatures`).
- Ran `cargo check -p aiosh-cli`: compiled clean with 0 errors.
