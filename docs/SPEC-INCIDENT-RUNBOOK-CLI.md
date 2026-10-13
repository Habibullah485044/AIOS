# Specification: Incident Response Runbooks & RustSec CLI Surface (SPEC-INCIDENT-RUNBOOK-CLI)

- **Status**: SPECIFIED
- **Date**: 2026-10-12
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
| `net <target>` | `<target> [--ports <p>] [--timeout-s <s>] [--grant <tok>] [--json]` | **RustScan** (fast async socket sweep) / Native TCP connect | `cap:net:scan` |
| `files <dir>` | `<dir> --pattern <pat> [--max-depth <d>] [--timeout-s <s>] [--grant <tok>] [--json]` | **Ripgrep (`rg`)** (memory-mapped) / Native regex search | `cap:fs:search` |
| `web <url>` | `<url> [--wordlist <wl>] [--depth <d>] [--timeout-s <s>] [--grant <tok>] [--json]` | **Feroxbuster** (async Tokio/Hyper) / Native `ureq` prober | `cap:web:probe` |

---

## 2. Invariants & Security Boundaries

- `IRCLI-INV1` (**Proof-of-Receipt Audit Logging**): Every execution of `aiosh runbook` or `aiosh scan` writes an atomic, append-only row into the SQLite WAL `AuditRing` containing target, args, outcome, and classifier provenance.
- `IRCLI-INV2` (**PEP Capability Token Check**): Network sweeps, filesystem IOC searches, web probes, and runbook step executions require explicit capability redemption checked through `pep.check`.
- `IRCLI-INV3` (**Zero Shell Interpretation & Parameter Whitelisting**): Subprocesses are executed via direct `argv` arrays (no `/bin/sh` or `cmd.exe`). Parameter values are bounded (`MAX_PARAM_LEN = 256`) and validated against `[a-zA-Z0-9_\-\.:/]`. Path traversal (`..`) is strictly prohibited.
- `IRCLI-INV4` (**Output and Error Bounding**): Stdout is capped at 16 KB and stderr at 4 KB (`OUTPUT_CAPTURE_LIMIT`, `STDERR_CAPTURE_LIMIT`). Process execution is terminated at deadline expiration (`timeout_s`).
- `IRCLI-INV5` (**ANSI & Escape Sequence Scrubbing**): All dynamic output is stripped of ANSI control characters (`\x1b[...]`) before presentation.

---

## 3. Data Structures & Result Envelopes

### 3.1 JSON Result Envelope
```json
{
  "ok": true,
  "tool": "scan.net",
  "audit_id": 1042,
  "target": "127.0.0.1",
  "data": {
    "open_ports": [22, 80, 443, 8080],
    "scanned_ports_count": 100,
    "elapsed_ms": 42
  },
  "error": null
}
```

### 3.2 Error Envelope
```json
{
  "ok": false,
  "tool": "scan.net",
  "audit_id": 1043,
  "target": "10.0.0.1",
  "data": null,
  "error": "PEP authorization failure: missing capability 'cap:net:scan'"
}
```

---

## 4. Exit Code Mapping
- `0`: Execution succeeded normally.
- `1`: Domain or validation error (e.g. invalid parameter format, missing required parameter, session not found).
- `2`: Command line syntax or usage error (e.g. unknown flag, missing target).
- `3`: PEP capability authorization refused or classifier denied.
- `4`: Execution watchdog timeout or I/O failure.
