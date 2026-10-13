# Unit Test Evidence: Incident Response Runbooks & RustSec CLI Surface (T-02987)

- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Incident Response Runbooks & RustSec Tooling / CLI surface
- **Task ID**: `T-02987`
- **Specification Document**: `docs/SPEC-INCIDENT-RUNBOOK-CLI.md`

## 1. Test Coverage & Assertions
Added focused unit test suites covering both the core substrate and the CLI command parser:

1. **Substrate Unit Tests (`code/aiosh-rust/aiosh-core/tests/test_sec_tools_unit.rs`)**:
   - `test_sec_tools_target_validation`: Validates IPv4, ports, hostnames, absolute paths, and URLs; asserts strict rejection of command injection characters (`;`, `|`, `&`, backticks, subshells) and path traversal (`..`).
   - `test_sec_tools_scan_net_bounds_and_execution`: Verifies network socket scanning argument bounding and safe single-port resolution.
   - `test_sec_tools_scan_files_matching`: Sets up temp files with forensic logs, verifies positive IOC line matches, line numbering, match counting, and non-existent path failure handling.
   - `test_sec_tools_scan_web_validation`: Validates HTTP/HTTPS scheme enforcement and endpoint candidate dispatch.

2. **Shell CLI Unit Tests (`code/aiosh-rust/aiosh-cli/src/main.rs:runbook_scan_cli_tests`)**:
   - `test_runbook_cli_commands`: Asserts exit codes for `--help` (0), `list` (0), `show` (0 on existing, 1 on missing, 2 on invalid usage), `init` (0), and unknown subcommands (2).
   - `test_scan_cli_commands`: Asserts exit codes for `--help` (0), `net` (2 on missing target, 0 on valid sweep), `files` (2 on missing directory or pattern, 0 on valid scan), `web` (2 on missing URL, 0 on valid endpoint check), and unknown subcommands (2).

## 2. Test Execution Results
- `cargo test -p aiosh-core --test test_sec_tools_unit`: 4/4 passed in 2.04s.
- `cargo test -p aiosh-cli --bin aiosh runbook_scan_cli_tests`: 2/2 passed in 5.32s.
- Total: 6/6 unit tests passed (100% green).
