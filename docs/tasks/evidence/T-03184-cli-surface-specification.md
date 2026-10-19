# Specification Evidence: AI Control Plane Model Backend Adapters CLI Surface (T-03184)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / CLI surface
- **Artifact**: `docs/tasks/evidence/T-03184-cli-surface-specification.md`
- **Specification Document**: `docs/SPEC-MODEL-BACKEND-ADAPTERS-CLI.md`
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS-SERVICE

---

## 1. Specification Overview

Task `T-03184` formalizes the interface and behavioral specifications for the Model Backend Adapters CLI surface (`aiosh model ...`) under document `SPEC-MODEL-BACKEND-ADAPTERS-CLI`.

### Formal Invariants Defined

| Invariant | Name | Guarantee |
| :--- | :--- | :--- |
| **`MODCLI-INV1`** | Command Schema Canonicalization | Subcommands: `list`, `show`, `health`, `complete`, `register` with strict argument validation and NUL rejection. |
| **`MODCLI-INV2`** | Proof-of-Restraint Invariant I-2 Gating | Pure read-only commands (`list`, `show`, `health`) consume 0 tokens. Consequential commands (`complete`, `register`) require `--token <grant_token>`. Missing/empty token exits `EXIT_UNAUTHORIZED = 3`. |
| **`MODCLI-INV3`** | Standardized Exit Code Taxonomy | `0` (Success), `1` (Failure), `2` (Usage error), `3` (Unauthorized), `4` (Timeout). JSON envelope parity across all subcommands. |
| **`MODCLI-INV4`** | Secret & Telemetry Redaction | Scrub Bearer tokens, API keys (`sk-*`, `ghp_*`), and sensitive credentials from outputs with `[REDACTED_SECRET]`. |
| **`MODCLI-INV5`** | Fallback & Timeout Bounds | Fallback depth bounded at 5, message count bounded at 100, deterministic fallback progression. |

---

## 2. Interface Contract

1. **`list`** (Read-Only):
   - Arguments: `[--provider <mock|openai_compatible|anthropic|gemini|ollama>] [--active-only] [--json]`
   - Token Requirement: 0 tokens.
2. **`show`** (Read-Only):
   - Arguments: `<backend_id> [--json]`
   - Token Requirement: 0 tokens.
3. **`health`** (Read-Only):
   - Arguments: `[backend_id] [--json]`
   - Token Requirement: 0 tokens.
4. **`complete`** (State-Mutating / Consequential Inference):
   - Arguments: `<backend_id> --prompt <text> [--temperature <float>] [--fallback <backend_id>]... --token <capability_token> [--json]`
   - Token Requirement: Valid capability token required (PoR I-2).
5. **`register`** (State-Mutating Endpoint Modification):
   - Arguments: `<backend_id> --provider <type> --model <name> [--base-url <url>] [--env <name>] [--timeout <ms>] --token <capability_token> [--json]`
   - Token Requirement: Valid capability token required (PoR I-2).

---

## 3. Verification

- Specification document created and reviewed: `docs/SPEC-MODEL-BACKEND-ADAPTERS-CLI.md`.
- Invariants `MODCLI-INV1..5` documented with deterministic test criteria.
- Validated with `tools/check_evidence.py`.
