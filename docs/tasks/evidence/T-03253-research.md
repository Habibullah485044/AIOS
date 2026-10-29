# T-03253 Research: AI Control Plane Model Backend Adapters Recovery & Validation

## 1. Executive Summary & Context
- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / recovery & validation
- **Task ID**: T-03253
- **Primary Goal**: Establish authoritative facts, constraints, threat models, and architectural prior art for validating and recovering Model Backend Adapters in AIOS.

---

## 2. Codebase Baseline & Existing Implementations

### 2.1 Fact: Existing Recovery Patterns in AIOS
- **`code/aiosh-mcp/aiosh_mcp/mcp_server_core_recovery.py`**:
  - Implements deep schema validation (`McpValidationReport`, `McpValidationIssue`) and quarantine recovery (`McpRecoveryResult`).
  - Invariant `MCPRECV-INV1`: Record count conservation (`total_records == valid_records + invalid_records`).
  - Invariant `MCPRECV-INV2`: Health consistency (`is_healthy == (len(issues) == 0 and invalid_records == 0)`).
  - Traversal immunity on paths via `validate_store_path()`: rejects `..`, Windows reserved device names (`CON`, `NUL`, etc.), NUL bytes, and alternate data streams (`:`).
  - Atomic quarantine: corrupted files are moved to `<filename>.corrupt.<timestamp>` and restored from clean backup or initialized with default schema.
- **`code/aiosh-mcp/aiosh_mcp/model_backend_adapters_data_model.py` & `service.py`**:
  - Defines `ModelBackendConfig`, `ModelProvider`, `CapabilityDescriptor`, and `ModelBackendService`.
  - Config contains `provider`, `model_name`, `endpoint_url`, `timeout_ms`, `max_tokens`, `cost_per_1k_tokens`.
  - Service supports dynamic backend switching and fallback chains, but currently lacks automatic corruption detection, schema validation for persisted config files, and atomic quarantine/recovery routines.

### 2.2 Assumptions vs Facts

| Item | Fact | Assumption | Resolution |
| :--- | :--- | :--- | :--- |
| **Persistence format** | Model backend configuration can be passed in-memory or persisted as JSON on disk (e.g. `config/models.json` or `.aios/models.json`). | Persisted JSON files may undergo concurrent truncated writes, manual operator corruption, or disk failures. | Must support atomic load, schema validation, quarantine of corrupted configs, and fallback creation. |
| **Token Gating (PoR I-2)** | Pure validation (`validate_config`) is a read-only introspection. | Recovery operations (`recover_config`, `quarantine_config`) write to disk/state and change configuration. | Validation requires 0 capability tokens; recovery requires valid capability token redemption. |
| **Fallback Target** | A safe fallback backend (`mock` or `local_ollama`) exists in the registry. | Fallback backend must always succeed and require zero external credentials. | When corrupt configuration is quarantined, restore default fallback configuration containing safe mock/offline backend. |

---

## 3. Authoritative Citations & Prior Art
1. **ADR-0035 §AF-2**: Uniform envelope return structure (`{status, ok, data/report, error, message}`).
2. **ADR-0037 / PoR Invariant I-2**: Proof-of-Restraint token budgeting: zero tokens for read introspection, mandatory token redemption for state-changing recovery.
3. **RFC 8259 (The JavaScript Object Notation Data Interchange Format)**: Parsing boundaries, strict UTF-8 decoding, handling unexpected EOF and malformed tokens.
4. **CWE-22 & CWE-59**: Path traversal and link resolution defenses.
5. **CWE-400**: Uncontrolled resource consumption; bounded file read size (`MAX_STORE_FILE_BYTES = 10 MiB`).

---

## 4. Key Architectural Decisions Needed

1. **Decision D1: Validation Schema & Error Codes**:
   - Introduce `ModelConfigValidationReport` and `ModelConfigValidationIssue`.
   - Error codes: `MODRECV_ERR_INVALID_PATH`, `MODRECV_ERR_CORRUPT_JSON`, `MODRECV_ERR_SCHEMA_VIOLATION`, `MODRECV_ERR_UNAUTHORIZED`, `MODRECV_ERR_IO`.
2. **Decision D2: Invariants for Recovery & Validation (`MODRECV-INV1..INV5`)**:
   - `MODRECV-INV1`: `total_configs == valid_configs + invalid_configs`.
   - `MODRECV-INV2`: `is_healthy == (len(issues) == 0 and invalid_configs == 0)`.
   - `MODRECV-INV3`: Path traversal and reserved device name immunity.
   - `MODRECV-INV4`: Proof-of-Restraint Invariant I-2 gating: validation is 0-token read; recovery requires capability token.
   - `MODRECV-INV5`: Atomic quarantine with backup before overwrite.
3. **Decision D3: MCP Tool Surface**:
   - `aios_model_validate_config(config_path: str) -> dict` (read-only, 0 tokens)
   - `aios_model_recover_config(config_path: str, capability_token: str, create_backup: bool = True) -> dict` (state-changing, token-gated)

---

## 5. Unknowns & Next Steps
- None blocking. Ready to proceed to specification task `T-03254`.
