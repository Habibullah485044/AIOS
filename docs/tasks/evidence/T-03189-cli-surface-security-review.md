# Security Review: AI Control Plane Model Backend Adapters CLI Surface (T-03189)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / CLI surface
- **Task ID**: `T-03189`
- **Specification Document**: `docs/SPEC-MODEL-BACKEND-ADAPTERS-CLI.md`
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS-SERVICE

---

## 1. Threat Modeling & Abuse Scenarios

| ID | Threat Vector | CWE | Attack Surface | Mitigation & Enforcement | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **AS-01** | Capability Token Bypass / Mutation Escalation | CWE-285 | `aiosh model complete`, `aiosh model register` | PoR Invariant I-2 gating: pure read operations (`list`, `show`, `health`) consume 0 tokens; state-mutating actions (`complete`, `register`) strictly require `--token <grant_token>`. Missing/empty/whitespace token exits `EXIT_UNAUTHORIZED = 3` fail-closed. | MITIGATED |
| **AS-02** | Credential & Telemetry Leakage | CWE-532, CWE-200 | CLI stdout, stderr, JSON envelopes | Invariant `MODCLI-INV4`: `redact_secrets()` sanitizes Bearer tokens, OpenAI keys (`sk-[a-zA-Z0-9_-]{10,}`), GitHub PATs (`ghp_*`), and sensitive environmental credentials before output or JSON formatting. | MITIGATED |
| **AS-03** | Fallback Exhaustion & Cascading Loop Flooding | CWE-400 | `aiosh model complete --fallback ...` | Invariant `MODCLI-INV5`: Fallback chain deduplicated and strictly capped at `MAX_FALLBACK_DEPTH = 5`. Prevents runaway cascades or loop attacks across model endpoints. | MITIGATED |
| **AS-04** | NUL Byte Injection & Parameter Smuggling | CWE-116, CWE-1286 | CLI argument vector | `parse_model_cli_args` performs pre-validation rejecting any argument containing NUL bytes (`\0`) with `EXIT_USAGE = 2`. | MITIGATED |
| **AS-05** | Denial of Service via Payload Flooding | CWE-400 | `--prompt <text>` | Message payloads bounded by `MAX_MESSAGE_BYTES = 1 MiB` and request message count bounded by `MAX_REQUEST_MESSAGES = 100`. Timeouts clamped to `[1000ms, 300000ms]`. | MITIGATED |
| **AS-06** | Path Traversal / Identifier Spoofing in Backend IDs | CWE-22, CWE-20 | `<backend_id>` | Positional backend identifier checked against regex whitelist `[a-zA-Z0-9_\-\.]`, length bounded to 64 chars, rejecting directory traversal (`..`, `/`, `\`). | MITIGATED |

---

## 2. Proof-of-Restraint (PoR) Conformance Verification

- **Invariant I-2 (Redeem-Before-Act)**:
  - Read-only operations (`list`, `show`, `health`) consume zero tokens.
  - Consequential inference (`complete`) and registry modification (`register`) fail closed before any network dispatch if an explicit capability token is not provided.
  - Test suites (`test_dispatch_por_token_gating`, `test_por_invariant_gating_mutations_rejected_without_token`) verify all bypass attempts return exit code `3`.

---

## 3. Hardening Recommendations for T-03190

1. **Max Length Boundary on Positional Arguments**: Add explicit length check (<= 64 chars) and directory traversal rejection directly in `parse_model_cli_args` for positional arguments.
2. **Temperature Bounds Checking in CLI**: Validate that `--temperature` is strictly within `[0.0, 2.0]` at CLI parsing time, returning `EXIT_USAGE = 2` if out of bounds.
3. **Redaction of User Prompts on Error**: Ensure that if a prompt contains accidental inline credentials, error messages returned in JSON envelopes are filtered through `redact_secrets()`.
4. **Rust Dual-Substrate Parity**: Replicate temperature bounds and positional argument length checks in `aiosh-core::model_backend_adapters_cli`.

---

## 4. Verification

- All 25 test suite cases in `code/aiosh-mcp/tests` pass.
- Rust unit tests in `aiosh-core` pass.
- Validated with `tools/check_evidence.py`.
