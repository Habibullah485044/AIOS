# Scaffold Evidence: Incident Response Runbooks Data Model (T-02965)

- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Incident Response Runbooks / Data Model
- **Task ID**: `T-02965`
- **Files Created / Modified**:
  - `code/aiosh-rust/aiosh-core/src/incident_runbook_data_model.rs` (created domain primitives and types)
  - `code/aiosh-rust/aiosh-core/src/lib.rs` (registered module and re-exported types)
  - `code/aiosh-mcp/aiosh_mcp/incident_runbook_data_model.py` (created Python dataclass models and parsing logic)
  - `code/aiosh-rust/aiosh-core/tests/test_incident_runbook_scaffold.rs` (created Rust scaffold tests)
  - `code/aiosh-mcp/tests/test_incident_runbook_scaffold.py` (created Python scaffold tests)

## 1. Scaffolded Symbols & Data Primitives
- **Enumerations**: `IncidentSeverity`, `IncidentCategory`, `RunbookPhase`, `RunbookTargetSubstrate`.
- **Structures**: `RunbookStep`, `RunbookSpec`, `RunbookCatalogSnapshot`.
- **Validation Functions**: `validate_identifier`, `validate_title`, `validate_text_length`.
- **Canonical Baselines**: Pre-configured playbooks for `RB-IR-MALWARE-01` and `RB-IR-ACCESS-01`.

## 2. Verification Results
- Rust: `cargo test --test test_incident_runbook_scaffold`: PASS (2/2 tests passed).
- Python: `pytest code/aiosh-mcp/tests/test_incident_runbook_scaffold.py`: PASS (2/2 tests passed).
- Clean compilations with zero warnings or broken imports.
