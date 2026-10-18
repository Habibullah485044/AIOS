# Verification & Evidence: AI Control Plane Model Backend Adapters Data Model (T-03172)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / data model
- **Artifact**: `docs/tasks/evidence/T-03172-data-model-verification-evidenc.md`
- **Milestone Span**: `T-03163` .. `T-03172`
- **Log Entry**: [docs/proof-of-restraint/LOG.md](../../proof-of-restraint/LOG.md)

---

## 1. Subsystem Verification Battery

### 1.1 Python Test Suite Execution
Executed all scaffold, implementation, unit, integration, and hardening test suites:
```
platform win32 -- Python 3.14.6, pytest-9.1.1
collected 24 items

code/aiosh-mcp/tests/test_model_backend_adapters_data_model_scaffold.py ......  [ 25%]
code/aiosh-mcp/tests/test_model_backend_adapters_data_model_impl.py ....        [ 41%]
code/aiosh-mcp/tests/test_model_backend_adapters_data_model_unit.py .....       [ 62%]
code/aiosh-mcp/tests/test_model_backend_adapters_data_model_integration.py ....[ 79%]
code/aiosh-mcp/tests/test_model_backend_adapters_data_model_hardening.py .....  [100%]

============================= 24 passed in 7.14s ==============================
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

- **`MODADAPT-INV1` (Role Canonicalization)**: Roles restricted strictly to `system`, `user`, `assistant`, or `tool`.
- **`MODADAPT-INV2` (Token Accounting Sum)**: Token usage requires non-negative integers satisfying `total_tokens == prompt_tokens + completion_tokens`.
- **`MODADAPT-INV3` (Secret Isolation)**: API keys must never be stored in plaintext. `api_key_env` stores only the environment variable name (max 64 chars, no `sk-` or `ghp_` prefixes).
- **`MODADAPT-INV4` (Strict Parameter Bounds)**: Temperature is bounded in `[0.0, 2.0]`, timeout in `[1000, 300000]` ms, and retries in `[0, 10]`.
- **`MODADAPT-INV5` (Proof-of-Restraint Invariant I-2 Gating)**: Read-only tool `aios_model_endpoint_list` requires 0 tokens; state-mutating tool `aios_model_endpoint_register` strictly requires a capability token.

---

## 3. Upstream Tasks Shipped in Feature Block

| Task ID | Stage | Shipped Evidence / Commit |
| :--- | :--- | :--- |
| `T-03163` | Research | `docs/tasks/evidence/T-03163-data-model-research.md` |
| `T-03164` | Specification | `docs/SPEC-MODEL-BACKEND-ADAPTERS.md` |
| `T-03165` | Scaffold | `model_backend_adapters_data_model.py` & `.rs` |
| `T-03166` | Implementation | `ModelEndpointRegistry`, default catalog |
| `T-03167` | Unit Test | Invariant test battery (`MODADAPT-INV1..5`) |
| `T-03168` | Integration | FastMCP tools `aios_model_endpoint_list`, `aios_model_endpoint_register` |
| `T-03169` | Security Review | 5 abuse scenarios, memory exhaustion defense |
| `T-03170` | Hardening | Traversal defense, URL scheme validation, 1 MiB payload limits |
| `T-03171` | Documentation | Updated `code/aiosh-mcp/README.md` |
