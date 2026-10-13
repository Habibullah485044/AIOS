# Documentation Evidence: Incident Response Runbooks & RustSec CLI Surface (T-02991)

- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Incident Response Runbooks / CLI surface: Documentation
- **Task ID**: `T-02991`
- **Specification**: `docs/SPEC-INCIDENT-RUNBOOK-CLI.md`

## 1. Summary of Documentation Deliverables
Comprehensive documentation for the Incident Response Runbooks CLI surface and RustSec security scanning substrate has been authored in `docs/SPEC-INCIDENT-RUNBOOK-CLI.md`:

1. **Operational Invocation Examples**:
   - `aiosh runbook list`, `show`, `start`, `step`, `confirm`, `status`, `abort`.
   - `aiosh scan net <target> [--ports <p>] [--timeout-ms <ms>] [--json]`.
   - `aiosh scan files <dir> --pattern <pat> [--max-depth <d>] [--max-size <bytes>] [--json]`.
   - `aiosh scan web <url> [--wordlist <wl>] [--timeout-ms <ms>] [--json]`.

2. **Hardening Constraints & Bounds**:
   - Detailed target string validation rules (`MAX_SCAN_TARGET_LEN = 256`, path traversal `..` prohibition, control character scrub, `[a-zA-Z0-9_\-\.:/\\~@]` whitelist).
   - Resource clamping rules for port sweeps (`MAX_PORTS_PER_SCAN = 10,000`, timeout `[10ms, 10,000ms]`).
   - File scanner limits (`MAX_FILE_SCAN_DEPTH = 32`, file size cap `16 MiB`, max matches `1,000`).
   - Web discovery limits (`MAX_WEB_PATHS = 1,000`, timeout `[50ms, 10,000ms]`).

3. **Honest Limitations & Tradeoffs**:
   - Full TCP handshake connect sweep vs raw SYN stealth mode.
   - Sequential recursive search memory-mapping fallback vs ripgrep daemon mode.

4. **Task Evidence Traceability**:
   - Linked evidence for T-02983 through T-02990.
