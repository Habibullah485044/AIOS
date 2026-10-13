# Specification: Incident Response Runbooks Configuration (SPEC-INCIDENT-RUNBOOK-CONFIG)

- **Status**: SPECIFIED
- **Date**: 2026-10-13
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Incident Response Runbooks / configuration
- **Binding**: NIST SP 800-61 Rev. 2, CISA Playbooks, ADR-0035 §C-2, ADR-0036 §B-1, PoR Invariant I-2
- **Target Implementation**:
  - Python MCP Module: `code/aiosh-mcp/aiosh_mcp/runbook_config.py`
  - Rust Core Substrate: `code/aiosh-rust/aiosh-core/src/runbook_config.rs`

---

## 1. Configuration Precedence Ladder

Resolution executes through a deterministic 4-level precedence ladder:

```
[Level 1: Explicit Caller Args] -> [Level 2: Environment Variables] -> [Level 3: Config File] -> [Level 4: Built-in Defaults]
```

### 1.1 Precedence Levels
1. **Level 1 (Caller Arguments)**: Explicit parameters passed to configuration resolution APIs.
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

## 4. Standard Error Codes

All configuration failures emit standardized error codes with the `RUNBOOKCONF_ERR_` prefix:
- `RUNBOOKCONF_ERR_PATH_TRAVERSAL`: Prohibited directory traversal (`..`) detected in path.
- `RUNBOOKCONF_ERR_FILE_SIZE`: Config file exceeds `MAX_CONFIG_FILE_BYTES` (64 KiB).
- `RUNBOOKCONF_ERR_PARSE`: Malformed JSON or syntax parsing failure.
- `RUNBOOKCONF_ERR_BOUNDS`: Numerical value out of acceptable bounds.
- `RUNBOOKCONF_ERR_IO`: Filesystem reading or I/O failure.
- `RUNBOOKCONF_ERR_VALIDATION`: Type mismatch or schema validation failure.

---

## 5. Invariants

- `RBCONF-INV1` (**Dual-Substrate Parity**): Rust and Python implementations must parse identical configurations to byte-stable identical values and identical source annotations.
- `RBCONF-INV2` (**Bounded Pre-allocation**): Config files larger than 64 KiB are rejected before JSON deserialization to prevent memory exhaustion attacks (CWE-400).
- `RBCONF-INV3` (**Fail-Safe Defaults**): Missing or corrupted config files emit honest warnings/audit logs and cleanly fall back to built-in canonical defaults without crashing the daemon or CLI.
