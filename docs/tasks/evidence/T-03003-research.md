# Research Evidence: Incident Response Runbooks Configuration (T-03003)

- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Incident Response Runbooks / configuration: Research
- **Task ID**: `T-03003`
- **Milestone**: Configuration Subsystem (T-03003 .. T-03012)
- **Status**: COMPLETE & VERIFIED

---

## 1. Context & Objectives
This research establishes the facts, constraints, configuration precedence ladder, and dual-substrate parity requirements for the configuration of Incident Response Runbooks across `aiosh-core` (Rust) and `aiosh-mcp` (Python).

---

## 2. Authoritative Sources & Standards
1. **AIOS Configuration Ladder Pattern (ADR-0035 §C-2, ADR-0036 §B-1)**:
   - Precedence: (1) Explicit caller argument -> (2) Environment variable -> (3) Config file (`docs/runbook_config.json`) -> (4) Canonical baseline defaults.
   - Provenance tracking: Every resolved config field records its `source` (`argument`, `env`, `file`, `default`, `env_invalid`, `config_invalid`).
2. **NIST SP 800-61 Rev. 2 (Section 3.2 — Incident Response Preparation & Tooling Config)**:
   - Standardizes maximum step timeout limits, execution watchdogs, and explicit capability assignments for containment playbooks.
3. **CISA Incident Response Playbooks**:
   - Operator approval gates and emergency auto-containment thresholds.
4. **RFC 8259 (JSON Data Interchange Format)**:
   - Byte-stable round-trip serialization and UTF-8 validation.

---

## 3. Fact vs Assumption Matrix

| Component | Fact | Assumption |
| :--- | :--- | :--- |
| **Config Precedence** | Existing AIOS subsystems (`threat_model_config`, `compliance_config`) use a 4-tier ladder. | Runbook subsystem must follow the exact same 4-tier precedence ladder for consistency. |
| **Config File Cap** | Config file size is capped at 64 KiB (`MAX_CONFIG_FILE_BYTES`) to prevent memory exhaustion (CWE-400). | `docs/runbook_config.json` will not exceed 64 KiB under operational conditions. |
| **Catalog Storage** | Default catalog path is `docs/runbook_catalog.json` with fallback to in-memory canonical baseline. | File store cap clamped to `[4 KiB, 16 MiB]`, default 1 MiB. |
| **Session Bounds** | In-memory session registry must have bounded capacity (`max_active_sessions`). | Default 1,000 active sessions clamped between `[1, 10,000]`. |
| **Dual Substrate** | Python (`aiosh_mcp`) and Rust (`aiosh-core`) must resolve identical configuration given the same environment. | Rust and Python struct field names and error codes must be byte-for-byte identical. |

---

## 4. Architectural Decisions

1. **Environment Variables**:
   - `AIOSH_RUNBOOK_CONFIG`: Overrides config file path (default `docs/runbook_config.json`).
   - `AIOSH_RUNBOOK_CATALOG_PATH`: Overrides catalog JSON path.
   - `AIOSH_RUNBOOK_AUTO_CONTAIN`: Boolean flag allowing automatic non-interactive step progression for low-risk actions.
2. **Error Codes Prefix**:
   - `RUNBOOKCONF_ERR_PATH_TRAVERSAL`
   - `RUNBOOKCONF_ERR_FILE_SIZE`
   - `RUNBOOKCONF_ERR_PARSE`
   - `RUNBOOKCONF_ERR_BOUNDS`
   - `RUNBOOKCONF_ERR_IO`
   - `RUNBOOKCONF_ERR_VALIDATION`
3. **Scope of Configuration Parameters**:
   - `catalog_path`: string (max 1024 chars, no `..` traversal).
   - `max_active_sessions`: int (`[1, 10000]`, default 1000).
   - `max_catalog_file_bytes`: int (`[4096, 16777216]`, default 1048576).
   - `default_step_timeout_seconds`: int (`[1, 86400]`, default 3600).
   - `require_operator_confirmation`: bool (default `True`).
