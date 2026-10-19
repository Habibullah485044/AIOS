# Verification & Evidence: AI Control Plane Model Backend Adapters Core Service (T-03182)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / core service
- **Artifact**: `docs/tasks/evidence/T-03182-core-service-verification-evidenc.md`
- **Milestone Span**: `T-03173` .. `T-03182`
- **Log Entry**: [docs/proof-of-restraint/LOG.md](../../proof-of-restraint/LOG.md)

---

## 1. Subsystem Verification Battery

### 1.1 Python Test Suite Execution
Executed all scaffold, implementation, unit, integration, and hardening test suites:
```
platform win32 -- Python 3.14.6, pytest-9.1.1
collected 20 items

code/aiosh-mcp/tests/test_model_backend_adapters_service_scaffold.py ....   [ 20%]
code/aiosh-mcp/tests/test_model_backend_adapters_service_impl.py ....       [ 40%]
code/aiosh-mcp/tests/test_model_backend_adapters_service_unit.py .....      [ 65%]
code/aiosh-mcp/tests/test_model_backend_adapters_service_integration.py .... [ 85%]
code/aiosh-mcp/tests/test_model_backend_adapters_service_hardening.py ...   [100%]

============================= 20 passed in 7.21s ==============================
```

### 1.2 Proof of Restraint Demonstration & Invariant I-2 Check
Executed `python -u tools/demo_por.py`:
- Step 1: Normal activity + shadow action, mint unused capability (`gr_demo_untouched`).
- Step 2: Anchor audit ring with signed Ed25519 checkpoints.
- Step 3: Generate restraint proof (`por_...`) for unused grant -> `PROVABLY_RESTRAINED`.
- Step 4: Standalone verifier exit code 0 (`valid: true`).
- Step 5: Attacker tampers by deleting shadow row and re-chaining -> Standalone verifier exit code 1 (`HEAD_HASH_MISMATCH`, `valid: false`).
- Result: **PASS** (Zero Escalation / Proof of Restraint verified).

---

## 2. Invariants Certified

- **`MODSERV-INV1` (Provider Dispatch Parity)**: Canonical adapter mappings across Mock, OpenAI-compatible, Anthropic Claude, Google Gemini, and Ollama.
- **`MODSERV-INV2` (Complete Token Accounting)**: Enforces `total_tokens == prompt_tokens + completion_tokens` across all returned model responses.
- **`MODSERV-INV3` (Resilient Fallback & Error Classification)**: Typed errors (`TIMEOUT`, `RATE_LIMIT`, `AUTH`, `UNAVAILABLE`) trigger fallback progression until candidate success or `MODSERV_ERR_FALLBACK_EXHAUSTED`.
- **`MODSERV-INV4` (Secret & Telemetry Isolation)**: Bearer tokens, `sk-*`, and `ghp_*` secrets are completely redacted from exceptions and logs.
- **`MODSERV-INV5` (Proof-of-Restraint Invariant I-2 Compliance)**: Gated mutation tool `aios_model_complete` strictly requires a capability token grant; `aios_model_service_health` is pure read-only consuming 0 tokens.

---

## 3. Upstream Tasks Shipped in Feature Block

| Task ID | Stage | Shipped Evidence / Commit |
| :--- | :--- | :--- |
| `T-03173` | Research | `docs/tasks/evidence/T-03173-core-service-research.md` |
| `T-03174` | Specification | `docs/SPEC-MODEL-BACKEND-ADAPTERS-SERVICE.md` |
| `T-03175` | Scaffold | `model_backend_adapters_service.py` & `.rs` |
| `T-03176` | Implementation | `ModelBackendService`, provider adapters, fallback |
| `T-03177` | Unit Test | Invariant test battery (`MODSERV-INV1..5`) |
| `T-03178` | Integration | FastMCP tools `aios_model_complete`, `aios_model_service_health` |
| `T-03179` | Security Review | 5 abuse scenarios, memory starvation, fallback recursion |
| `T-03180` | Hardening | Message ceiling, fallback depth limit (5), deduplication |
| `T-03181` | Documentation | Updated `code/aiosh-mcp/README.md` |
