# Specification: Incident Response Runbooks & RustSec CLI Surface (SPEC-INCIDENT-RUNBOOK-CLI)

- **Status**: IMPLEMENTED & HARDENED
- **Date**: 2026-10-13
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Incident Response Runbooks & RustSec Tooling / CLI surface
- **Binding**: NIST SP 800-61 Rev. 2, CISA Playbooks, ADR-0035 §C-2, ADR-0036 §B-1, PoR Invariant I-2
- **Target Implementation**:
  - Rust Core Substrate: `code/aiosh-rust/aiosh-core/src/sec_tools.rs`
  - Rust Shell CLI: `code/aiosh-rust/aiosh-cli/src/main.rs` (`cmd_runbook`, `cmd_scan`)

---

## 1. CLI Commands & Arguments

### 1.1 `aiosh runbook` (Alias: `aiosh rb`)

| Subcommand | Arguments / Flags | Description | Audit Tool Name |
| :--- | :--- | :--- | :--- |
| `list` | `[--category <cat>] [--severity <sev>] [--json]` | Lists cataloged containment and remediation runbooks. | `runbook.list` |
| `show <id>` | `<id> [--json]` | Displays runbook metadata, steps, capabilities, and phase triggers. | `runbook.show` |
| `init` | `[--path <path>] [--force]` | Generates default canonical incident runbook catalog. | `runbook.init` |
| `start <id>` | `<id> [--incident-id <id>] [--param <k=v>...] [--grant <token>] [--json]` | Initializes and parameterizes an active execution session. | `runbook.start` |
| `step <session_id>` | `<session_id> [--confirm] [--token <tok>] [--operator <op>] [--json]` | Dispatches the next step. Halts if confirmation is required. | `runbook.step` |
| `confirm <session_id>` | `<session_id> --operator <op> --token <tok>` | Submits operator credentials and token to unblock gated step. | `runbook.confirm` |
| `abort <session_id>` | `<session_id> [--reason <reason>]` | Aborts active session and skips remaining steps. | `runbook.abort` |
| `status <session_id>` | `<session_id> [--json]` | Inspects session status, current step index, and step logs. | `runbook.status` |

### 1.2 `aiosh scan` (RustSec Security Substrate)

| Subcommand | Arguments / Flags | Substrate & Fallback | Required Capability |
| :--- | :--- | :--- | :--- |
| `net <target>` | `<target> [--ports <p>] [--timeout-ms <ms>] [--grant <tok>] [--json]` | Fast native TCP connect / socket sweep | `cap:net:scan` |
| `files <dir>` | `<dir> --pattern <pat> [--max-depth <d>] [--max-size <bytes>] [--grant <tok>] [--json]` | Native recursive file regex scanner | `cap:fs:search` |
| `web <url>` | `<url> [--wordlist <wl>] [--timeout-ms <ms>] [--grant <tok>] [--json]` | Native HTTP endpoint discovery | `cap:web:probe` |

---

## 2. Invariants & Security Boundaries

- `IRCLI-INV1` (**Proof-of-Receipt Audit Logging**): Every execution of `aiosh runbook` or `aiosh scan` writes an atomic, append-only row into the SQLite WAL `AuditRing` containing target, args, outcome, and classifier provenance.
- `IRCLI-INV2` (**PEP Capability Token Check**): Network sweeps, filesystem IOC searches, web probes, and runbook step executions require explicit capability redemption checked through `pep.check`.
- `IRCLI-INV3` (**Zero Shell Interpretation & Parameter Whitelisting**): Subprocesses are executed via direct `argv` arrays (no `/bin/sh` or `cmd.exe`). Parameter values are bounded (`MAX_PARAM_LEN = 256`) and validated against `[a-zA-Z0-9_\-\.:/\\~@]`. Path traversal (`..`) and control characters (`\0`, `\n`, `\r`) are strictly prohibited.
- `IRCLI-INV4` (**Output and Error Bounding**): Stdout is capped at 16 KB and stderr at 4 KB (`OUTPUT_CAPTURE_LIMIT`, `STDERR_CAPTURE_LIMIT`). Process execution is terminated at deadline expiration (`timeout_s`).
- `IRCLI-INV5` (**ANSI & Escape Sequence Scrubbing**): All dynamic output is stripped of ANSI control characters (`\x1b[...]`) before presentation.

---

## 3. Operational Examples

### 3.1 Runbook Session Lifecycle

```bash
# 1. Inspect available incident response runbooks
aiosh runbook list

# 2. View details and verification steps of a specific runbook
aiosh runbook show RB-001-MALWARE-CONTAINMENT

# 3. Start a new execution session with parameters
aiosh runbook start RB-001-MALWARE-CONTAINMENT --param target_pid=4096 --param target_uid=1001 --json

# 4. Advance through steps
aiosh runbook step 550e8400-e29b-41d4-a716-446655440000

# 5. Provide operator confirmation for sensitive steps
aiosh runbook confirm 550e8400-e29b-41d4-a716-446655440000 --operator sec_admin --token CONFIRM_TOK_99

# 6. Check active session progress
aiosh runbook status 550e8400-e29b-41d4-a716-446655440000 --json
```

### 3.2 RustSec Security Substrate Scanning

```bash
# Fast socket sweep of open ports on localhost
aiosh scan net 127.0.0.1 --ports 22,80,443,8080 --timeout-ms 200 --json

# Search for IOC patterns (e.g. Cobalt Strike pipe / credential regex)
aiosh scan files /var/log --pattern "eval\(base64_decode" --max-depth 5 --json

# Probe common web paths on an endpoint
aiosh scan web http://127.0.0.1:8080 --wordlist admin,login,api,metrics --timeout-ms 500 --json
```

---

## 4. Hardening Rules & Known Limitations

1. **Target String Validation**:
   - Must not contain directory traversal sequences (`..`).
   - Must not exceed `MAX_SCAN_TARGET_LEN = 256` bytes.
   - Must not contain control characters (`\0`, `\n`, `\r`).
   - Must match positive whitelist `[a-zA-Z0-9_\-\.:/\\~@]`.

2. **Resource Clamping**:
   - Port sweep: Ports are clamped to `[1, 65535]`. Total ports per scan capped at `MAX_PORTS_PER_SCAN = 10,000`. Socket timeout clamped to `[10ms, 10,000ms]`.
   - File search: Max recursion depth clamped to `MAX_FILE_SCAN_DEPTH = 32`. File read size clamped to `MAX_FILE_SCAN_SIZE = 16 MiB`. Match count capped at `MAX_FILE_MATCHES = 1,000`.
   - Web discovery: Max paths capped at `MAX_WEB_PATHS = 1,000`. Request timeout clamped to `[50ms, 10,000ms]`.

3. **Known Limitations**:
   - TCP connect scanning establishes full handshakes (SYN-ACK-ACK) rather than raw SYN stealth scans because raw sockets require elevated superuser/root capabilities.
   - File scanning uses sequential recursive directory iteration; for massive multi-terabyte filesystems, ripgrep external binary offloading is recommended once installed.

---

## 5. Exit Code Mapping

- `0`: Execution succeeded normally.
- `1`: Domain or execution error (e.g. invalid parameter format, missing required parameter, session not found, socket bind failure).
- `2`: Command line syntax or usage error (e.g. unknown flag, missing target).
- `3`: PEP capability authorization refused or classifier denied.
- `4`: Execution watchdog timeout or I/O failure.

---

## 6. Task Evidence Cross-References

- Research: [`T-02983-research.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02983-research.md)
- Specification: [`T-02984-spec.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02984-spec.md)
- Scaffold: [`T-02985-scaffold.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02985-scaffold.md)
- Implementation: [`T-02986-implementation.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02986-implementation.md)
- Unit Testing: [`T-02987-unit-test.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02987-unit-test.md)
- Integration: [`T-02988-integration.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02988-integration.md)
- Security Review: [`T-02989-security.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02989-security.md)
- Hardening: [`T-02990-hardening.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02990-hardening.md)
