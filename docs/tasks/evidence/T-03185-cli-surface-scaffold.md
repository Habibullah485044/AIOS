# Scaffold Evidence: AI Control Plane Model Backend Adapters CLI Surface (T-03185)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / CLI surface
- **Artifact**: `docs/tasks/evidence/T-03185-cli-surface-scaffold.md`
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS-CLI

---

## 1. Scaffold Implementations

1. **Python CLI Substrate**:
   - File: `code/aiosh-mcp/aiosh_mcp/model_backend_adapters_cli.py`
   - Registered in `code/aiosh-mcp/aiosh_mcp/__init__.py`
   - Defines standard exit codes: `EXIT_SUCCESS=0`, `EXIT_FAILURE=1`, `EXIT_USAGE=2`, `EXIT_UNAUTHORIZED=3`, `EXIT_TIMEOUT=4`
   - Defines `ModelCliOutput` envelope with automatic secret redaction (`[REDACTED_SECRET]`)
   - Implements argument parser `parse_model_cli_args` with NUL byte rejection
   - Implements `dispatch_model_cli` with Proof-of-Restraint Invariant I-2 token gating (pure read costs 0 tokens; `complete`/`register` requires `--token`)

2. **Rust Core Substrate**:
   - File: `code/aiosh-rust/aiosh-core/src/model_backend_adapters_cli.rs`
   - Registered in `code/aiosh-rust/aiosh-core/src/lib.rs`
   - Defines `ModelCliSubcommand` and `ModelCliOutput`
   - Implements Rust `parse_model_cli_args`

3. **Scaffold Tests**:
   - File: `code/aiosh-mcp/tests/test_model_backend_adapters_cli_scaffold.py`
   - Verifies exit codes contract, output envelopes, argument parsing, and PoR Invariant I-2 token gating

---

## 2. Test Verification

```
platform win32 -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0
code\aiosh-mcp\tests\test_model_backend_adapters_cli_scaffold.py .... [100%]
4 passed in 0.30s
```

`cargo check -p aiosh-core` passed with zero errors.
Evidence validated with `tools/check_evidence.py`.
