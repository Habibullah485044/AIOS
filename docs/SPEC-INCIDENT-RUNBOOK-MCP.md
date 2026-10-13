# Specification: Incident Response Runbooks & RustSec MCP/API Surface (SPEC-INCIDENT-RUNBOOK-MCP)

- **Status**: SPECIFIED
- **Date**: 2026-10-13
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Incident Response Runbooks & RustSec Tooling / MCP/API surface
- **Binding**: NIST SP 800-61 Rev. 2, CISA Playbooks, ADR-0035 §D-2, ADR-0036 §B-1, PoR Invariant I-2
- **Target Implementation**:
  - Python MCP Module: `code/aiosh-mcp/aiosh_mcp/incident_runbook_mcp.py`
  - Python MCP Server Registration: `code/aiosh-mcp/aiosh_mcp/server.py` (`aios_runbook`, `aios_scan`)

---

## 1. Tool Interfaces & Schema

### 1.1 `aios_runbook`

Exposed as Model Context Protocol tool `@mcp.tool()`:

```python
def aios_runbook(
    action: str,
    runbook_id: str | None = None,
    session_id: str | None = None,
    incident_id: str | None = None,
    parameters: dict[str, str] | None = None,
    category: str | None = None,
    severity: str | None = None,
    operator_id: str | None = None,
    token: str | None = None,
    reason: str | None = None,
    grant_id: str | None = None,
) -> dict:
```

#### Supported Actions
| Action | Description | Required Args | PEP Capability |
| :--- | :--- | :--- | :--- |
| `list` | Lists cataloged incident runbooks. | None (optional: `category`, `severity`) | None (read-only) |
| `show` | Displays runbook metadata, steps, capabilities. | `runbook_id` | None (read-only) |
| `init` | Initializes canonical baseline catalog. | None | `cap:runbook:admin` |
| `start` | Initializes execution session with parameters. | `runbook_id`, `incident_id` | `cap:runbook:execute` |
| `step` | Dispatches the next step in session. | `session_id` | `cap:runbook:execute` |
| `confirm` | Submits operator credential and confirmation token. | `session_id`, `operator_id`, `token` | `cap:runbook:execute` |
| `status` | Inspects execution progress and step logs. | `session_id` | None (read-only) |
| `abort` | Aborts active execution session. | `session_id` | `cap:runbook:execute` |

### 1.2 `aios_scan` (RustSec Security Scanning Substrate)

Exposed as Model Context Protocol tool `@mcp.tool()`:

```python
def aios_scan(
    action: str,
    target: str,
    ports: str | None = None,
    pattern: str | None = None,
    wordlist: str | None = None,
    timeout_ms: int | None = None,
    max_depth: int | None = None,
    max_size: int | None = None,
    grant_id: str | None = None,
) -> dict:
```

#### Supported Actions
| Action | Description | Substrate & Logic | PEP Capability |
| :--- | :--- | :--- | :--- |
| `net` | TCP port sweep / socket connection probe. | Python socket / RustSec backend | `cap:net:scan` |
| `files` | Recursive file search for regex pattern. | Recursive walk & regex search | `cap:fs:search` |
| `web` | HTTP endpoint path probing. | Urllib / HTTP probe against wordlist | `cap:web:probe` |

---

## 2. Invariants & Security Boundaries

- `IRMCP-INV1` (**Authoritative Gate Dispatch**): Every invocation of `aios_runbook` and `aios_scan` routes through `_recorded_call()` / `_dispatch.dispatch()`, writing an atomic AuditRing row.
- `IRMCP-INV2` (**Capability Redemption**): Mutating runbook actions and scanning operations require a valid `grant_id` with appropriate capability token. Read-only actions operate without grant.
- `IRMCP-INV3` (**Input Sanitization & Parameter Whitelisting**): Target strings, parameters, and paths are validated against character whitelists, bounds caps, and path traversal restrictions (`..`).
- `IRMCP-INV4` (**Standard Result Envelopes**): Errors produce structured envelopes (`{ok: false, action, error, audit_id}`) and never leak bare unhandled framework exceptions.
- `IRMCP-INV5` (**Session Thread Safety & Bounds**): Active sessions in `RunbookSessionStore` are clamped to max 1,000 instances with thread-safe locking.

---

## 3. Exit Codes & Error Envelopes

### 3.1 Standard Success Envelope
```json
{
  "ok": true,
  "action": "start",
  "data": {
    "session_id": "550e8400-e29b-41d4-a716-446655440000",
    "runbook_id": "RB-IR-MALWARE-01",
    "status": "pending"
  },
  "audit_id": 1042
}
```

### 3.2 Awaiting Confirmation Envelope
```json
{
  "ok": false,
  "action": "step",
  "error": "RUNBOOK_ERR_MISSING_CONFIRMATION: Step requires operator confirmation",
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "awaiting_confirmation": true,
  "audit_id": 1043
}
```

### 3.3 Error Envelope
```json
{
  "ok": false,
  "action": "start",
  "error": "RUNBOOK_ERR_SESSION_NOT_FOUND: Runbook 'RB-UNKNOWN' not found",
  "audit_id": 1044
}
```
