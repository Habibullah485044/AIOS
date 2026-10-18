# Scaffold Evidence: AI Control Plane Model Backend Adapters Data Model (T-03165)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / data model
- **Artifact**: `docs/tasks/evidence/T-03165-data-model-scaffold.md`
- **Created Modules**:
  - Python: `code/aiosh-mcp/aiosh_mcp/model_backend_adapters_data_model.py`
  - Rust: `code/aiosh-rust/aiosh-core/src/model_backend_adapters_data_model.rs`
  - Rust exports: `code/aiosh-rust/aiosh-core/src/lib.rs`
- **Scaffold Test Suite**: `code/aiosh-mcp/tests/test_model_backend_adapters_data_model_scaffold.py` (6 passed)

---

## 1. Scaffold Implementation Details

1. **Python Data Structures**:
   - `ModelProviderType`: Enum for `OPENAI_COMPATIBLE`, `ANTHROPIC`, `GEMINI`, `OLLAMA`, `MOCK`.
   - `ModelCapabilities`: Dataclass capturing default and custom model feature flags.
   - `ModelEndpointConfig`: Structured endpoint config enforcing secret isolation and bounds.
   - `ModelMessage`: Role-validated message format.
   - `ModelUsage`: Token accounting with non-negativity and sum invariants.
   - `ModelRequest` and `ModelResponse`: Unified request and response structures.
2. **Rust Parity**:
   - Corresponding structs and enums created with Serde serialization support in `aiosh-core`.
3. **Validation & Invariants**:
   - `validate_role` enforces `MODADAPT-INV1`.
   - `ModelUsage.validate_invariants` enforces `MODADAPT-INV2`.
   - `ModelEndpointConfig.validate` enforces `MODADAPT-INV3` and `MODADAPT-INV4`.
