# Hardening Evidence: AI Control Plane Model Backend Adapters CLI Surface (T-03190)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / CLI surface
- **Artifact**: `docs/tasks/evidence/T-03190-cli-surface-hardening.md`
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS-CLI

---

## 1. Hardening Defenses Implemented

Task `T-03190` addresses the findings from the security review (`T-03189`), implementing strict input bounding, anti-traversal defenses, and fail-closed validation across Python and Rust substrates:

1. **Positional Identifier Defenses**:
   - Bounds: Length capped at 64 characters (`<= 64`).
   - Anti-Traversal: Rejects `..`, `/`, and `\` in identifiers with `EXIT_USAGE = 2`.
   - Control Characters: Prohibits ASCII control characters and NUL bytes (`\0`).

2. **Temperature Bounds Enforcement**:
   - Clamped to valid range `[0.0, 2.0]`. Out-of-bounds values exit immediately with `EXIT_USAGE = 2` during argument parsing.

3. **Fallback Chain Depth Clamping**:
   - Restricts repeated `--fallback` arguments to `MAX_FALLBACK_DEPTH = 5`. Attempts to provide more than 5 fallbacks reject with `EXIT_USAGE = 2`.

4. **Timeout Boundary Clamping**:
   - Requires `--timeout` to fall strictly within `[1000, 300000]` ms (1s to 5m), preventing integer underflow/overflow or resource exhaustion.

5. **Secret Redaction Hardening**:
   - Guarantees `redact_secrets()` sanitizes Bearer tokens, OpenAI keys (`sk-*`), and GitHub PATs (`ghp_*`) on all output pathways, including JSON error structures and standard console output streams.

---

## 2. Test Execution Verification

### Python Substrate
```
platform win32 -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0
code\aiosh-mcp\tests\test_model_backend_adapters_cli_scaffold.py .... [ 13%]
code\aiosh-mcp\tests\test_model_backend_adapters_cli_impl.py ......   [ 33%]
code\aiosh-mcp\tests\test_model_backend_adapters_cli_unit.py ............ [ 73%]
code\aiosh-mcp\tests\test_model_backend_adapters_cli_integration.py ...   [ 83%]
code\aiosh-mcp\tests\test_model_backend_adapters_cli_hardening.py .....  [100%]
30 passed in 0.89s
```

### Rust Substrate
```
running 5 tests
test model_backend_adapters_cli::tests::test_dispatch_list_and_show ... ok
test model_backend_adapters_cli::tests::test_dispatch_por_token_enforcement ... ok
test model_backend_adapters_cli::tests::test_exit_codes_constants ... ok
test model_backend_adapters_cli::tests::test_parse_nul_byte_rejection ... ok
test model_backend_adapters_cli::tests::test_parse_subcommands_valid ... ok
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 469 filtered out; finished in 0.14s
```

Evidence validated with `tools/check_evidence.py`.
