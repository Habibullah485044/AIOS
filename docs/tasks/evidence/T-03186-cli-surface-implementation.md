# Implementation Evidence: AI Control Plane Model Backend Adapters CLI Surface (T-03186)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / CLI surface
- **Artifact**: `docs/tasks/evidence/T-03186-cli-surface-implementation.md`
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS-CLI

---

## 1. Implementation Overview

Task `T-03186` completes the implementation of the Model Backend Adapters CLI Surface across dual substrates (Python and Rust).

### Subcommands Implemented

1. **`list`**:
   - Lists registered backend adapters.
   - Supports filtering by `--provider` and `--active-only`.
   - Supports plain text and structured `--json` envelopes.
   - Proof-of-Restraint token requirement: 0 tokens (pure read).

2. **`show`**:
   - Inspects target endpoint configuration (`backend_id`).
   - Rejects missing positional argument with `EXIT_USAGE = 2`.
   - Handles missing endpoint with `EXIT_FAILURE = 1`.
   - Proof-of-Restraint token requirement: 0 tokens (pure read).

3. **`health`**:
   - Evaluates system-wide adapter readiness or specific endpoint status.
   - Validates adapter availability across loaded providers.
   - Proof-of-Restraint token requirement: 0 tokens (pure read).

4. **`complete`**:
   - Dispatches model completion request through `ModelBackendService`.
   - Enforces PoR Invariant I-2: requires valid `--token`, exiting with `EXIT_UNAUTHORIZED = 3` if absent.
   - Handles fallback chains with bounds enforcement.
   - Supports plain text and structured `--json` responses.

5. **`register`**:
   - Dynamically registers new inference endpoint into registry.
   - Enforces PoR Invariant I-2: requires valid `--token`, exiting with `EXIT_UNAUTHORIZED = 3` if absent.
   - Validates provider string and endpoint parameters.

---

## 2. Test Verification

```
platform win32 -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0
code\aiosh-mcp\tests\test_model_backend_adapters_cli_scaffold.py .... [ 40%]
code\aiosh-mcp\tests\test_model_backend_adapters_cli_impl.py ......   [100%]
10 passed in 0.51s
```

`cargo check -p aiosh-core` passed with zero errors.
Evidence validated with `tools/check_evidence.py`.
