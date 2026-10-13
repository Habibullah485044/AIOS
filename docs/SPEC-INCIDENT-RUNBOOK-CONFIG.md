# Specification: Incident Response Runbooks Configuration (SPEC-INCIDENT-RUNBOOK-CONFIG)

- **Status**: SHIPPED
- **Date**: 2026-10-13
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Incident Response Runbooks / configuration
- **Binding**: NIST SP 800-61 Rev. 2, CISA Playbooks, ADR-0035 §C-2, ADR-0036 §B-1, PoR Invariant I-2
- **Shipped Implementations**:
  - Python MCP Module: `code/aiosh-mcp/aiosh_mcp/runbook_config.py`
  - Rust Core Substrate: `code/aiosh-rust/aiosh-core/src/runbook_config.rs`
- **Evidence Trail**:
  - Research: [T-03003-research.md](tasks/evidence/T-03003-research.md)
  - Specification: [T-03004-specification.md](tasks/evidence/T-03004-specification.md)
  - Scaffold: [T-03005-scaffold.md](tasks/evidence/T-03005-scaffold.md)
  - Implementation: [T-03006-configuration-implementation.md](tasks/evidence/T-03006-configuration-implementation.md)
  - Unit Tests: [T-03007-configuration-unit-test.md](tasks/evidence/T-03007-configuration-unit-test.md)
  - Integration: [T-03008-configuration-integration.md](tasks/evidence/T-03008-configuration-integration.md)
  - Security Review: [T-03009-security.md](tasks/evidence/T-03009-security.md)
  - Hardening: [T-03010-configuration-hardening.md](tasks/evidence/T-03010-configuration-hardening.md)

---

## 1. Configuration Precedence Ladder

Resolution executes through a deterministic 4-level precedence ladder:

```
[Level 1: Explicit Caller Args] -> [Level 2: Environment Variables] -> [Level 3: Config File] -> [Level 4: Built-in Defaults]
```

### 1.1 Precedence Levels
1. **Level 1 (Caller Arguments)**: Explicit parameters passed to configuration resolution APIs (`catalog_path`, `max_active_sessions`, etc.).
2. **Level 2 (Environment Variables)**:
   - `AIOSH_RUNBOOK_CONFIG`: Overrides path to config JSON file (default `docs/runbook_config.json`).
   - `AIOSH_RUNBOOK_CATALOG_PATH`: Overrides path to runbook catalog store.
   - `AIOSH_RUNBOOK_MAX_SESSIONS`: Clamped integer `[1, 10000]`.
   - `AIOSH_RUNBOOK_STEP_TIMEOUT`: Clamped integer `[1, 86400]`.
   - `AIOSH_RUNBOOK_REQUIRE_CONFIRMATION`: Boolean string (`"true"`, `"false"`, `"1"`, `"0"`).
3. **Level 3 (Config File)**: JSON file located at `AIOSH_RUNBOOK_CONFIG` or default `docs/runbook_config.json`. File size strictly capped at 64 KiB (`MAX_CONFIG_FILE_BYTES`).
4. **Level 4 (Built-in Defaults)**: Canonical fallback defaults guaranteeing zero panic and zero unhandled errors.

---

## 2. Configuration Parameters & Bounds

| Field Name | Type | Default Value | Valid Range / Bounds | Description |
| :--- | :--- | :--- | :--- | :--- |
| `catalog_path` | `String` | `"docs/runbook_catalog.json"` | Max 1024 chars, no `..` | Absolute or relative path to catalog store. |
| `max_active_sessions` | `u32` / `int` | `1000` | `[1, 10000]` | Maximum active execution sessions held in memory. |
| `max_catalog_file_bytes` | `u64` / `int` | `1048576` (1 MiB) | `[4096, 16777216]` (16 MiB) | Hard cap on catalog file storage size. |
| `default_step_timeout_seconds`| `u64` / `int` | `3600` (1 hour) | `[1, 86400]` (24 hours) | Default per-step execution watchdog timeout. |
| `require_operator_confirmation`| `bool` | `True` | `true` or `false` | Gate requiring operator credential token for sensitive steps. |

---

## 3. Provenance Tracking & Sources

Every resolved configuration object carries a `sources` mapping recording where each field originated:
- `"argument"`: Field resolved from caller-provided argument.
- `"env"`: Field resolved from environment variable.
- `"file"`: Field resolved from config JSON file.
- `"default"`: Field resolved from canonical default.
- `"env_invalid"`: Environment variable value failed validation/bounds; safely fell back.
- `"config_invalid"`: Config file value failed validation/bounds; safely fell back.

---

## 4. Production Usage & Invocations

### 4.1 FastMCP Tool Call
To inspect active configuration via the MCP surface:
```json
{
  "tool": "aios_runbook",
  "action": "config"
}
```
Response format:
```json
{
  "ok": true,
  "action": "config",
  "config": {
    "catalog_path": "docs/runbook_catalog.json",
    "max_active_sessions": 1000,
    "max_catalog_file_bytes": 1048576,
    "default_step_timeout_seconds": 3600,
    "require_operator_confirmation": true,
    "sources": {
      "catalog_path": "default",
      "max_active_sessions": "default",
      "max_catalog_file_bytes": "default",
      "default_step_timeout_seconds": "default",
      "require_operator_confirmation": "default"
    }
  },
  "audit_id": 42
}
```

### 4.2 Python SDK
```python
from aiosh_mcp.runbook_config import resolve_runbook_config, safe_resolve_runbook_config

# Strict resolution (raises ValueError on validation or traversal failures)
config = resolve_runbook_config(max_active_sessions=500)
print(f"Catalog: {config.catalog_path}, Max Sessions: {config.max_active_sessions}")

# Safe resolution envelope (never raises; returns envelope with error details and defaults on failure)
res = safe_resolve_runbook_config(config_path="../bad/path.json")
if not res["ok"]:
    print(f"Resolution failed safely with code {res['error_code']}: {res['error']}")
```

### 4.3 Rust Substrate
```rust
use aiosh_core::runbook_config::{resolve_runbook_config, safe_resolve_runbook_config, RunbookConfigOverrides};

let overrides = RunbookConfigOverrides {
    max_active_sessions: Some(500),
    ..Default::default()
};

let config = resolve_runbook_config(Some(&overrides)).expect("resolution failed");
assert_eq!(config.max_active_sessions, 500);

let safe_envelope = safe_resolve_runbook_config(None);
assert!(safe_envelope.ok);
```

---

## 5. Constraints & Known Limitations

1. **Immutable at Runtime via MCP**: Configuration is immutable over the `aios_runbook` MCP surface. Clients cannot mutate configuration files on disk via RPC commands (prevents remote privilege escalation).
2. **Config File Cap**: Configuration JSON files larger than 64 KiB are rejected unconditionally (`RUNBOOKCONF_ERR_FILE_SIZE`). Large data catalogs must reside in the separate catalog store file (`docs/runbook_catalog.json`).
3. **No Dynamic Hot-Reload Watcher**: Modifying environment variables or configuration files requires re-calling resolution or daemon restart; no inotify watcher is spawned.
4. **Traversal Prevention**: Relative paths containing `..` tokens are strictly prohibited (`RUNBOOKCONF_ERR_PATH_TRAVERSAL`).
