# Unit Test Evidence: AI Control Plane Model Backend Adapters CLI Surface (T-03187)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / CLI surface
- **Artifact**: `docs/tasks/evidence/T-03187-cli-surface-unit-test.md`
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS-CLI

---

## 1. Test Suite Coverage & Invariants

Task `T-03187` establishes unit test coverage across both Python and Rust implementations:

1. **`MODCLI-INV1` (Command Schema & Parsing)**:
   - Validates proper handling of flags (`--provider`, `--active-only`, `--prompt`, `--temperature`, `--fallback`, `--token`, `--json`).
   - Verifies rejection of empty subcommands, unknown subcommands, and NUL byte injections.

2. **`MODCLI-INV2` (Proof-of-Restraint Gating)**:
   - Validates that read operations (`list`, `show`, `health`) consume 0 capability tokens.
   - Validates that mutating operations (`complete`, `register`) strictly require `--token`, failing closed with `EXIT_UNAUTHORIZED = 3` on missing, empty, or whitespace tokens.

3. **`MODCLI-INV3` (Standardized Exit Codes & JSON Parity)**:
   - Verifies taxonomy: `0` (Success), `1` (Failure), `2` (Usage), `3` (Unauthorized), `4` (Timeout).
   - Validates JSON envelope parity on both success (`ok: true`) and error (`ok: false`) conditions.

4. **`MODCLI-INV4` (Secret & Telemetry Redaction)**:
   - Validates redaction of Bearer tokens, `sk-*` keys, and `ghp_*` tokens across terminal strings and structured JSON error envelopes.

5. **`MODCLI-INV5` (Fallback & Execution Bounds)**:
   - Tests multi-stage fallback dispatch across endpoints.

---

## 2. Test Execution Verification

### Python Substrate
```
code\aiosh-mcp\tests\test_model_backend_adapters_cli_scaffold.py .... [ 18%]
code\aiosh-mcp\tests\test_model_backend_adapters_cli_impl.py ......   [ 45%]
code\aiosh-mcp\tests\test_model_backend_adapters_cli_unit.py ............ [100%]
22 passed in 3.97s
```

### Rust Substrate
```
running 5 tests
test model_backend_adapters_cli::tests::test_dispatch_list_and_show ... ok
test model_backend_adapters_cli::tests::test_dispatch_por_token_enforcement ... ok
test model_backend_adapters_cli::tests::test_exit_codes_constants ... ok
test model_backend_adapters_cli::tests::test_parse_nul_byte_rejection ... ok
test model_backend_adapters_cli::tests::test_parse_subcommands_valid ... ok
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 469 filtered out; finished in 0.09s
```

Evidence integrity checked via `tools/check_evidence.py`.
