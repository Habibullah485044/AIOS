# Hardening Evidence: Incident Response Runbooks & RustSec CLI Surface (T-02990)

- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Incident Response Runbooks / CLI surface: Hardening
- **Task ID**: `T-02990`
- **Specification**: `docs/SPEC-INCIDENT-RUNBOOK-CLI.md`

## 1. Summary of Hardening Implementations
Implemented robust defense-in-depth hardening across `aiosh-core` and `aiosh-cli` for the security scanning substrate and runbook execution commands addressing findings in `T-02989-security.md`:

1. **Target String Input Sanitization & Whitelist (CWE-22, CWE-78, CWE-1287)**:
   - Enhanced `validate_scan_target(target)` in `aiosh-core/src/sec_tools.rs`:
     - Enforces non-empty targets.
     - Clamps target length to `MAX_SCAN_TARGET_LEN = 256` (`SEC_ERR_BOUNDS_EXCEEDED`).
     - Prohibits directory traversal `..` explicitly.
     - Prohibits null bytes (`\0`), newlines (`\n`), and carriage returns (`\r`).
     - Strictly enforces positive character whitelist `[a-zA-Z0-9_\-\.:/\\~@]`, permitting Windows paths (including 8.3 short paths) and Unix paths while blocking shell metacharacters, subshells, backticks, semicolons, and pipes.

2. **Resource Bounds & Timeout Clamping (DoS Mitigation)**:
   - Socket connection sweeps enforce timeout clamping between `[10ms, 10,000ms]`.
   - Port bounds strictly clamped `[1, 65535]` with port count cap `MAX_PORTS_PER_SCAN = 10,000`.
   - File scanner enforces `MAX_FILE_SCAN_DEPTH = 32`, file size cap `MAX_FILE_SCAN_SIZE = 16 MiB`, and match limit cap `MAX_FILE_MATCHES = 1,000`.
   - Web endpoint wordlist scanner caps path count `MAX_WEB_PATHS = 1,000` and enforces bounded per-request timeouts `[50ms, 10,000ms]`.

3. **Safe Error Envelopes & Zero Silent Failures**:
   - Every CLI execution returns structured exit codes (0 for success, 1 for execution error, 2 for validation failure) and writes structured JSON output or clear stderr diagnostics.
   - Resource cleanup is guaranteed through standard RAII scopes on sockets, file handles, and temp directories.

## 2. Test Verification
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml -p aiosh-core --test test_sec_tools_unit` (4/4 tests passed).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml -p aiosh-core --test test_sec_tools_integration` (3/3 tests passed).
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml -p aiosh-cli --bin aiosh runbook_scan_cli_tests` (2/2 tests passed).
