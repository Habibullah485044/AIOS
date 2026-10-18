# Unit Test Evidence: AI Control Plane Model Backend Adapters Data Model (T-03167)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / data model
- **Artifact**: `docs/tasks/evidence/T-03167-data-model-unit-test.md`
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS
- **Test Suites**:
  - Python: `code/aiosh-mcp/tests/test_model_backend_adapters_data_model_unit.py` (5 passed)
  - Rust: `code/aiosh-rust/aiosh-core/tests/test_model_backend_adapters_data_model_unit.rs`

---

## 1. Test Battery & Invariant Assertions

1. **`MODADAPT-INV1` (Role Canonicalization)**:
   - Valid roles (`system`, `user`, `assistant`, `tool`) validated case-insensitively.
   - Non-canonical or empty roles fail closed with `MODADAPT_ERR_INVALID_ROLE`.
2. **`MODADAPT-INV2` (Token Accounting Invariant)**:
   - Non-negative token validation.
   - Strict assertion `total_tokens == prompt_tokens + completion_tokens`.
3. **`MODADAPT-INV3` (Secret Isolation)**:
   - `api_key_env` accepts environment variable references (`AIOS_OPENAI_KEY`).
   - Explicitly rejects raw plaintext tokens (`sk-...`, `ghp_...`, length > 64) with `MODADAPT_ERR_SECRET_LEAK`.
4. **`MODADAPT-INV4` (Parameter Bounds Enforcement)**:
   - Temperature bounded in `[0.0, 2.0]`.
   - Timeout bounded in `[1000, 300000]` ms.
   - Max retries bounded in `[0, 10]`.
5. **Request Boundary Constraints**:
   - Rejection of empty message histories, empty model IDs, and non-positive max tokens.
