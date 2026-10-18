# Integration Evidence: AI Control Plane Model Backend Adapters Data Model (T-03168)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / data model
- **Artifact**: `docs/tasks/evidence/T-03168-data-model-integration.md`
- **FastMCP Tools Integrated**: `aios_model_endpoint_list`, `aios_model_endpoint_register` in `code/aiosh-mcp/aiosh_mcp/server.py`
- **Integration Test Suite**: `code/aiosh-mcp/tests/test_model_backend_adapters_data_model_integration.py` (4 passed)

---

## 1. System Integration Details

1. **FastMCP Surface Registration**:
   - `aios_model_endpoint_list`: Pure read-only query returning all active model backend adapter configs without exposing secrets.
   - `aios_model_endpoint_register`: State-changing tool to register or update model adapter endpoints.
2. **Behavior Verification**:
   - `aios_model_endpoint_list` returns default canonical endpoints (`mock-default`, `openai-primary`, `anthropic-primary`, `gemini-primary`, `ollama-local`).
   - `aios_model_endpoint_register` strictly enforces Proof-of-Restraint Invariant I-2: calls without capability tokens fail closed with unauthorized errors.
   - Calls with valid capability tokens successfully persist new or updated endpoints into the live in-memory registry.
3. **Safety & Zero Secret Leakage**:
   - Enforces `MODADAPT-INV3`: rejects raw plaintext keys in `api_key_env`.
   - Enforces `MODADAPT-INV5`: zero escalation across all read/write paths.
