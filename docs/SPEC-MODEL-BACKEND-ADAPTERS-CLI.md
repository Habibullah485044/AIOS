# Specification & Documentation: AI Control Plane Model Backend Adapters CLI Surface

**Document ID**: SPEC-MODEL-BACKEND-ADAPTERS-CLI  
**Lifecycle Target**: T-03183..T-03192 (Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / CLI surface)  
**Contract Reference**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS-SERVICE  
**Status**: ACTIVE  

---

## 1. Overview & Architectural Role

The **Model Backend Adapters CLI Surface** provides an operator-facing and scriptable terminal interface (`aiosh model ...`) for inspecting model endpoints, querying runtime health, executing completions with fallback progression, and dynamically registering inference backends.

All interactions adhere strictly to Proof-of-Restraint Invariant I-2 (read-only queries consume 0 capability tokens; state-mutating actions strictly require `--token`) and output standardized exit codes and JSON envelopes across dual substrates (Python `aiosh_mcp.model_backend_adapters_cli` and Rust `aiosh_core::model_backend_adapters_cli`).

---

## 2. Invariants & Architectural Guarantees

| Invariant | Target | Validation Rule | Description |
| :--- | :--- | :--- | :--- |
| **`MODCLI-INV1`** | Command Schema Canonicalization | Subcommands: `list`, `show`, `health`, `complete`, `register` | Strict argument syntax with NUL byte rejection and positional bounds |
| **`MODCLI-INV2`** | Proof-of-Restraint Gating | `complete` and `register` require `--token` | Missing/empty token exits `EXIT_UNAUTHORIZED = 3` fail-closed |
| **`MODCLI-INV3`** | Standardized Exit Code Taxonomy | `0` (Success), `1` (Failure), `2` (Usage), `3` (Unauthorized), `4` (Timeout) | Deterministic exit status and structured `--json` output |
| **`MODCLI-INV4`** | Secret & Telemetry Redaction | Never print plaintext keys or Bearer tokens | Error messages and verbose outputs scrub secrets with `[REDACTED_SECRET]` |
| **`MODCLI-INV5`** | Fallback & Timeout Bounds | Fallback depth bounded at 5, message count bounded at 100 | Graceful error classification, loop protection, and recovery |

---

## 3. Command Syntax & Options

### 3.1 Grammar & Subcommand Reference

```
aiosh model [SUBCOMMAND] [OPTIONS]

SUBCOMMANDS:
  list                List registered model backend endpoints
                      Flags:
                        --provider <TYPE>       Filter by provider (mock, openai_compatible, anthropic, gemini, ollama)
                        --active-only           Filter active endpoints only
                        --json                  Output catalog in JSON format

  show <BACKEND_ID>   Inspect endpoint configuration, capabilities, and timeouts
                      Flags:
                        --json                  Output endpoint details in JSON format

  health [BACKEND_ID] Query runtime availability and loaded adapter readiness
                      Flags:
                        --json                  Output health status in JSON format

  complete <BACKEND_ID> Execute inference prompt through primary/fallback endpoints
                      Flags:
                        --prompt <TEXT>         Inference prompt text (mandatory)
                        --temperature <FLOAT>   Sampling temperature in [0.0, 2.0] (default: 0.7)
                        --fallback <ID>         Ordered fallback backend identifier (max depth: 5)
                        --token <GRANT_TOKEN>   Capability grant token (mandatory, PoR I-2)
                        --json                  Output response envelope in JSON format

  register <BACKEND_ID> Dynamically register a new inference backend endpoint
                      Flags:
                        --provider <TYPE>       Provider adapter type (mandatory)
                        --model <NAME>          Target model name/identifier (mandatory)
                        --base-url <URL>        Base API endpoint URL (optional)
                        --env <VAR_NAME>        Environment variable name holding secret (optional)
                        --timeout <MS>          Request timeout in milliseconds [1000, 300000] (default: 30000)
                        --token <GRANT_TOKEN>   Capability grant token (mandatory, PoR I-2)
                        --json                  Output registration confirmation in JSON format
```

---

## 4. Exit Codes & JSON Output Envelopes

### 4.1 Exit Code Taxonomy

| Code | Constant | Meaning |
| :--- | :--- | :--- |
| `0` | `EXIT_SUCCESS` | Operation completed successfully |
| `1` | `EXIT_FAILURE` | Operation failed (endpoint missing, service error, network failure) |
| `2` | `EXIT_USAGE` | Invalid CLI arguments, bounds violation, NUL byte detected, syntax error |
| `3` | `EXIT_UNAUTHORIZED` | Capability token missing, empty, or whitespace for state-mutating command (PoR I-2) |
| `4` | `EXIT_TIMEOUT` | Operation exceeded configured timeout bounds |

### 4.2 Structured Output Schema (`--json`)

#### Successful Response:
```json
{
  "status": "success",
  "ok": true,
  "exit_code": 0,
  "response": {
    "id": "resp-uuid",
    "model": "gpt-4o",
    "content": "Completion response text",
    "finish_reason": "stop",
    "latency_ms": 12.4
  }
}
```

#### Error Envelope:
```json
{
  "status": "error",
  "ok": false,
  "exit_code": 3,
  "error_message": "MODSERV_ERR_UNAUTHORIZED: subcommand 'complete' requires a capability token (--token)"
}
```

---

## 5. Security & Verification Architecture

- **Dual-Substrate Implementation**:
  - Python: `aiosh_mcp.model_backend_adapters_cli`
  - Rust: `aiosh_core::model_backend_adapters_cli`
- **Proof-of-Restraint Enforcement**: Pure read-only commands cost zero tokens; all consequential inference or registration commands fail-closed at the CLI boundary before invocation.
- **Secret Hygiene**: Regex scrubbing via `redact_secrets()` sanitizes Bearer credentials, `sk-*` API keys, and `ghp_*` tokens across error strings and printed logs.
- **Boundary Defenses**:
  - Positional identifier maximum length: 64 characters
  - Traversal prohibition: rejects `..`, `/`, and `\`
  - Temperature clamping: `[0.0, 2.0]`
  - Timeout clamping: `[1000, 300000]` ms
  - Max fallback chain: 5 endpoints
