# Specification: AI Control Plane Model Backend Adapters CLI Surface

**Document ID**: SPEC-MODEL-BACKEND-ADAPTERS-CLI  
**Lifecycle Target**: T-03183..T-03192 (Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / CLI surface)  
**Contract Reference**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS-SERVICE  
**Status**: ACTIVE  

---

## 1. Overview & Architectural Role

The **Model Backend Adapters CLI Surface** provides an operator-facing and scriptable command line interface (`aiosh model ...`) for inspecting model endpoints, querying runtime health, executing completions with fallback progression, and dynamically registering inference backends.

All interactions adhere strictly to Proof-of-Restraint Invariant I-2 (read-only queries consume 0 capability tokens; state-mutating actions strictly require `--token`) and output standardized exit codes and JSON envelopes.

---

## 2. Invariants & Architectural Guarantees

| Invariant | Target | Validation Rule | Description |
| :--- | :--- | :--- | :--- |
| **`MODCLI-INV1`** | Command Schema Canonicalization | Subcommands: `list`, `show`, `health`, `complete`, `register` | Strict argument syntax with NUL byte rejection |
| **`MODCLI-INV2`** | Proof-of-Restraint Gating | `complete` and `register` require `--token` | Missing/empty token exits `EXIT_UNAUTHORIZED = 3` fail-closed |
| **`MODCLI-INV3`** | Standardized Exit Code Taxonomy | `0` (Success), `1` (Failure), `2` (Usage), `3` (Unauthorized), `4` (Timeout) | Deterministic exit status and structured `--json` output |
| **`MODCLI-INV4`** | Secret & Telemetry Redaction | Never print plaintext keys or Bearer tokens | Error messages and verbose outputs scrub secrets with `[REDACTED_SECRET]` |
| **`MODCLI-INV5`** | Fallback & Timeout Bounds | Fallback depth bounded at 5, message count bounded at 100 | Graceful error classification and recovery |

---

## 3. Command Syntax & Options

### 3.1 Subcommand Reference

1. **`list`** (Read-Only):
   - Syntax: `aiosh model list [--provider <mock|openai_compatible|anthropic|gemini|ollama>] [--active-only] [--json]`
   - Behavior: Enumerate configured backend adapters.

2. **`show`** (Read-Only):
   - Syntax: `aiosh model show <backend_id> [--json]`
   - Behavior: Displays endpoint metadata, timeouts, retries, and capabilities.

3. **`health`** (Read-Only):
   - Syntax: `aiosh model health [backend_id] [--json]`
   - Behavior: Queries runtime availability and loaded adapter status.

4. **`complete`** (State-Mutating / Consequential Inference, PEP Gated):
   - Syntax: `aiosh model complete <backend_id> --prompt <text> [--temperature <float>] [--fallback <backend_id>]... --token <capability_token> [--json]`
   - Behavior: Executes completion through `ModelBackendService`. Requires valid capability token.

5. **`register`** (State-Mutating Endpoint Modification, PEP Gated):
   - Syntax: `aiosh model register <backend_id> --provider <type> --model <name> [--base-url <url>] [--env <name>] [--timeout <ms>] --token <capability_token> [--json]`
   - Behavior: Adds or updates endpoint in registry. Requires valid capability token.

---

## 4. Exit Codes & JSON Output Envelopes

### 4.1 Exit Codes
- `EXIT_SUCCESS: int = 0`
- `EXIT_FAILURE: int = 1`
- `EXIT_USAGE: int = 2`
- `EXIT_UNAUTHORIZED: int = 3`
- `EXIT_TIMEOUT: int = 4`

### 4.2 Structured Output Schema (`--json`)
```json
{
  "status": "success",
  "ok": true,
  "exit_code": 0,
  "data": { ... }
}
```
Or on error:
```json
{
  "status": "error",
  "ok": False,
  "exit_code": 3,
  "error_message": "MODSERV_ERR_UNAUTHORIZED: capability token required"
}
```

---

## 5. Security & Verification Strategy

- **Dual-Substrate Parity**: Implemented in Python (`aiosh_mcp.model_backend_adapters_cli`) and Rust (`aiosh_core::model_backend_adapters_cli`).
- **Comprehensive Testing**: Unit tests, CLI argument parsing tests, integration tests against live registry/service, and hardening tests.
