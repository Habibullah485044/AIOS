# Specification: Compliance Mapping Configuration (SPEC-COMPLIANCE-CONFIG)

**Status**: Standard / Locked  
**Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / Configuration  
**Contract Reference**: `docs/tasks/evidence/T-02904-spec.md`  
**Cross-Substrate Support**: Python MCP (`aiosh_mcp.compliance_config`) & Rust CLI / Core (`aiosh_core::compliance_config`)  

---

## 1. Overview & Purpose

The Compliance Mapping Configuration subsystem provides a unified, cross-substrate configuration resolver for Compliance Mapping. It manages store location selection, file size bounds, maximum entry capacities, and query/mutation audit logging policies without breaking Invariant I-2 or weakening PEP enforcement.

---

## 2. Precedence Ladder

When selecting the target compliance mapping store and parameters, AIOS evaluates a 4-level precedence ladder (highest priority wins):

```
+-------------------------------------------------------------+
| Level 1: Explicit Command-Line Argument                      |
|          `--path <filepath>` (Unconditional operator intent)|
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
| Level 2: Environment Variable Override                      |
|          `AIOSH_COMPLIANCE_MAP_PATH` (CWE-15 hygiene gated) |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
| Level 3: Configuration File                                 |
|          1. `--config <path>` (CLI argument)                |
|          2. `AIOSH_COMPLIANCE_CONFIG` (Env var)             |
|          3. `docs/compliance_config.json` (Default file)    |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
| Level 4: Built-in Defaults                                  |
|          Store Path: `docs/compliance_map.json`             |
+-------------------------------------------------------------+
```

---

## 3. Configuration File Schema & Limits

Config files are formatted in JSON and adhere to strict resource bounds:

```json
{
  "version": "1.0.0",
  "store_path": "docs/compliance_map.json",
  "max_store_file_bytes": 1048576,
  "max_entries": 1024,
  "audit_all_queries": false,
  "audit_all_mutations": true
}
```

### Constraints and Clamping Rules

| Field | Default | Min Bound | Max Bound | Behavior on Violation |
|---|---|---|---|---|
| `max_store_file_bytes` | `1,048,576` (1 MiB) | `4,096` (4 KiB) | `16,777,216` (16 MiB) | Clamped to `[4096, 16MiB]` |
| `max_entries` | `1,024` | `1` | `4,096` | Clamped to `[1, 4096]` |
| `audit_all_queries` | `false` | `false` | `true` | Boolean parsed |
| `audit_all_mutations` | `true` | `true` | `true` | **IMMUTABLE**: Forced to `true` (Cannot be disabled) |
| Config File Size | N/A | `1 byte` | `65,536` (64 KiB) | **Fail-closed**: `COMPLIANCECONF_ERR_FILE_SIZE` |

---

## 4. Usage & Working Examples

### 4.1 CLI Invocations (Rust)

```bash
# 1. Default invocation (uses docs/compliance_map.json)
aiosh compliance list

# 2. Specifying a custom configuration file
aiosh compliance list --config my_config.json

# 3. Explicit store path override (Level 1 precedence)
aiosh compliance list --path custom_store.json

# 4. View configuration resolution help
aiosh compliance -h
```

### 4.2 Python / MCP Invocation

```python
from aiosh_mcp import compliance_config

# Resolve configuration across current environment and args
resolved = compliance_config.resolve(
    arg_path=None,
    arg_config="docs/compliance_config.json"
)

print(resolved["config"]["store_path"])
print(resolved["source"]["store_path"])  # Returns "file", "env", "argument", or "default"
```

---

## 5. Security & Invariants

1. **Hygiene Gate (CWE-15 / CWE-22)**:
   Environment variables (`AIOSH_COMPLIANCE_MAP_PATH`, `AIOSH_COMPLIANCE_CONFIG`) containing path traversal patterns (`..`), control characters (`ord < 32`), null bytes, or exceeding 1024 bytes are rejected (`source = "env_invalid"`).
2. **Pre-Parse File Size Defense (CWE-400)**:
   Config files exceeding 64 KiB fail closed before parsing to prevent denial-of-service via memory exhaustion.
3. **Audit Immutability**:
   `audit_all_mutations` cannot be configured to `false`. Mutating operations will always emit an audit record.
4. **Proof of Restraint (Invariant I-2)**:
   Configuration resolution is read-only. Store modifications remain gated by capability token redemption.

---

## 6. Known Limitations

- Configuration files only support UTF-8 JSON. YAML, TOML, and XML are intentionally unsupported to keep parsing zero-dependency.
- Symlinks pointing outside the repository root are subject to standard OS filesystem sandboxing rules.
- Remote / network URLs as config paths are prohibited.
