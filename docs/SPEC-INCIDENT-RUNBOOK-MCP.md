# Specification & Reference: Incident Response Runbooks & RustSec MCP/API Surface (SPEC-INCIDENT-RUNBOOK-MCP)

- **Status**: IMPLEMENTED & HARDENED
- **Date**: 2026-10-13
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Incident Response Runbooks & RustSec Tooling / MCP/API surface
- **Binding**: NIST SP 800-61 Rev. 2, CISA Playbooks, ADR-0035 §D-2, ADR-0036 §B-1, PoR Invariant I-2
- **Target Implementation**:
  - Python MCP Module: `code/aiosh-mcp/aiosh_mcp/incident_runbook_mcp.py`
  - Python MCP Server Registration: `code/aiosh-mcp/aiosh_mcp/server.py` (`aios_runbook`, `aios_scan`)

---

## 1. Tool Interfaces & Schema

### 1.1 `aios_runbook`

Exposed as Model Context Protocol tool `@mcp.tool()` on `FastMCP("aiosh-mcp")`:

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

Exposed as Model Context Protocol tool `@mcp.tool()` on `FastMCP("aiosh-mcp")`:

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

## 2. Copy-Pasteable MCP Tool Invocations

### 2.1 Discover and Run an Incident Response Runbook

```python
# 1. Query available runbooks
catalog = aios_runbook(action="list")

# 2. Inspect runbook details
spec = aios_runbook(action="show", runbook_id="RB-IR-MALWARE-01")

# 3. Start a containment session with parameters
session = aios_runbook(
    action="start",
    runbook_id="RB-IR-MALWARE-01",
    incident_id="INC-2026-MALWARE-01",
    parameters={"target_pid": "4096", "target_uid": "1001"},
    grant_id="grant_runbook_token_01",
)
session_id = session["session_id"]

# 4. Advance execution steps
step_1 = aios_runbook(action="step", session_id=session_id)

# 5. Check session progress
status = aios_runbook(action="status", session_id=session_id)
```

### 2.2 Security Scanning via MCP

```python
# Scan open ports on target
ports_res = aios_scan(
    action="net",
    target="127.0.0.1",
    ports="22,80,443,8080",
    timeout_ms=100,
    grant_id="grant_scan_token_01",
)

# Search directory for malicious pattern
files_res = aios_scan(
    action="files",
    target="/var/log",
    pattern="unauthorized_root_login",
    max_depth=4,
    grant_id="grant_fs_token_01",
)

# Discover web endpoints
web_res = aios_scan(
    action="web",
    target="http://127.0.0.1:8080",
    wordlist="admin,metrics,health",
    timeout_ms=200,
    grant_id="grant_web_token_01",
)
```

---

## 3. Hardening Invariants & Constraints

- `IRMCP-INV1` (**Dual-Gate Authoritative Dispatch**): Every invocation of `aios_runbook` and `aios_scan` routes through `_recorded_mcp_call()` -> `_dispatch.dispatch()`, verifying the rule-pack classifier (C-1..C-4) and PEP grant.
- `IRMCP-INV2` (**Single Audit Row per Call**): Every tool call commits exactly one append-only audit row into the SQLite WAL `audit_ring` with full provenance (`policy_revision`, `classify_rule_ids`, `audit_id`).
- `IRMCP-INV3` (**Strict Input Validation & Whitelisting**): Targets are validated against `MAX_SCAN_TARGET_LEN = 256`, path traversal `..` prohibition, control character scrubbing, and `[a-zA-Z0-9_\-\.:/\\~@]` character whitelisting. Parameters are bounded by `MAX_RUNBOOK_PARAMS_COUNT = 32` and `MAX_RUNBOOK_PARAM_LEN = 256`.
- `IRMCP-INV4` (**Confirmation Gate Gating**): High-risk steps requiring confirmation halt progression in `AWAITING_CONFIRMATION` state until operator confirmation is validated.
- `IRMCP-INV5` (**Resource Clamping**): Socket timeouts are clamped to `[10ms, 10,000ms]`, ports capped at 10,000, recursion depth capped at 32, file read sizes capped at 16 MiB, and active sessions capped at 1,000.

---

## 4. Known Limitations

1. **Local Stdio Transport**: Standard MCP communication runs over stdio JSON-RPC transport; multi-tenant remote network streaming requires an authentication sidecar proxy.
2. **Sequential Connect Sweeps**: Network port probes use standard TCP connect (`SOCK_STREAM`) rather than raw SYN packets, requiring normal networking permissions and no raw socket privilege.
3. **In-Memory Active Session Registry**: Active sessions are retained in an in-memory thread-safe registry with 1,000 entry capacity. Long-term archived runbook executions are stored as audit records and JSON snapshots.

---

## 5. Task Evidence Cross-References

- Research: [`T-02993-research.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02993-research.md)
- Specification: [`T-02994-spec.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02994-spec.md)
- Scaffold: [`T-02995-scaffold.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02995-scaffold.md)
- Implementation: [`T-02996-implementation.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02996-implementation.md)
- Unit Testing: [`T-02997-unit-test.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02997-unit-test.md)
- Integration: [`T-02998-integration.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02998-integration.md)
- Security Review: [`T-02999-security.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02999-security.md)
- Hardening: [`T-03000-hardening.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03000-hardening.md)
