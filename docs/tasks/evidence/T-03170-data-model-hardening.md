# Hardening Evidence: AI Control Plane Model Backend Adapters Data Model (T-03170)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / data model
- **Artifact**: `docs/tasks/evidence/T-03170-data-model-hardening.md`
- **Bindings**: ADR-0035 §F-1, ADR-0035 §G-1, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS
- **Test Suite**: `code/aiosh-mcp/tests/test_model_backend_adapters_data_model_hardening.py` (5 passed)

---

## 1. Hardening & Defenses Implemented

1. **Backend ID Traversal & Injection Rejection**:
   - `validate_backend_id` strictly requires regex `^[a-zA-Z0-9_\-\.]{1,64}$`.
   - Explicitly rejects directory traversal (`..`), path separators (`/`, `\`), and NUL bytes (`\0`).
   - Prevents registry pollution and file injection.

2. **Base URL Scheme Restriction & Control Character Immunity**:
   - `validate_base_url` restricts protocol scheme to `http://`, `https://`, `ws://`, or `wss://`.
   - Blocks dangerous pseudo-schemes (`file://`, `javascript:`, `ftp://`).
   - Rejects ASCII control characters (`ord < 32` or `127`) preventing CRLF and header injection.

3. **Denial-of-Service (DoS) Payload Limiting**:
   - `ModelMessage` bounds message payload size to `MAX_MESSAGE_BYTES = 1024 * 1024` (1 MiB).
   - Prevents memory exhaustion attacks via oversized request bodies.

4. **Secret Isolation & Bounded Parameters**:
   - Maintains `MODADAPT-INV3` forbidding plaintext secrets (`sk-`, `ghp_`, length > 64) in `api_key_env`.
   - Bounds `timeout_ms` within `[1000, 300000]` and `max_retries` within `[0, 10]`.

5. **Cross-Substrate Parity**:
   - Implemented identically across Python (`aiosh_mcp.model_backend_adapters_data_model`) and Rust (`aiosh_core::model_backend_adapters_data_model`).
