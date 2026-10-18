# Security Review Evidence: AI Control Plane Model Backend Adapters Data Model (T-03169)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / data model
- **Artifact**: `docs/tasks/evidence/T-03169-data-model-security-review.md`
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS

---

## 1. Threat Modeling & Abuse Scenario Assessment

We evaluated 5 realistic threat vectors against the Model Backend Adapters Data Model:

### Scenario 1: Plaintext API Key Leakage & Credential Exposure (CWE-312 / CWE-522)
- **Attack Vector**: An operator or automated agent mistakenly passes a live bearer token or provider key (`sk-live-...`, `ghp_...`, `Bearer ...`) into `api_key_env` or configuration payloads.
- **Analysis**:
  - `ModelEndpointConfig.validate()` strictly enforces `MODADAPT-INV3` by rejecting strings starting with `sk-`, `ghp_`, or exceeding 64 characters with `MODADAPT_ERR_SECRET_LEAK`.
  - The configuration only stores environment variable names (e.g. `"OPENAI_API_KEY"`).
  - Inspection via `aios_model_endpoint_list` surfaces only the environment variable name, never the secret value itself.
- **Verdict**: **MITIGATED**.

### Scenario 2: Unauthenticated Endpoint Redirection & Invariant I-2 Bypass (CWE-306 / CWE-862)
- **Attack Vector**: An unprivileged actor calls `aios_model_endpoint_register` without a capability token to redirect model inference endpoints to a malicious proxy (`base_url="http://attacker.com/v1"`).
- **Analysis**:
  - `aios_model_endpoint_register` gates all modifications behind `capability_token`.
  - Empty or invalid tokens fail closed with `MODADAPT_ERR_UNAUTHORIZED`.
  - Read-only inspections (`aios_model_endpoint_list`) require zero tokens, preserving zero-cost observation without write escalation.
- **Verdict**: **MITIGATED** (Enforces PoR Invariant I-2).

### Scenario 3: Denial-of-Service via Registry Flooding & Memory Exhaustion (CWE-400 / CWE-770)
- **Attack Vector**: An adversary attempts to flood the in-memory registry with millions of dynamic endpoint descriptors to trigger Out-Of-Memory (OOM).
- **Analysis**:
  - `ModelEndpointRegistry` enforces a strict capacity ceiling of `MAX_ENDPOINTS = 64`.
  - Registration beyond 64 endpoints raises `MODADAPT_ERR_BOUNDS` fail-closed.
- **Verdict**: **MITIGATED**.

### Scenario 4: Role Injection & Model Jailbreaking via Non-Canonical Roles (CWE-20 / CWE-74)
- **Attack Vector**: An adversary passes pseudo-roles (`role="system_override"`, `role="developer"`, `role="admin"`) to inject instructions or bypass prompt safeguards.
- **Analysis**:
  - `validate_role` enforces `MODADAPT-INV1` across Python and Rust: only `system`, `user`, `assistant`, `tool` are permitted.
  - Any other string triggers `MODADAPT_ERR_INVALID_ROLE` fail-closed.
- **Verdict**: **MITIGATED**.

### Scenario 5: Parameter Manipulation & Unbounded Worker Thread Stalling (CWE-20)
- **Attack Vector**: An attacker supplies extreme parameter values (negative temperature, NaN, timeout of hours) to stall worker threads or trigger numerical instability.
- **Analysis**:
  - `validate_temperature` strictly clamps temperature to `[0.0, 2.0]`.
  - `timeout_ms` is strictly validated within `[1000, 300000]` ms (1s to 5m).
  - `max_retries` is capped in `[0, 10]`.
- **Verdict**: **MITIGATED**.

---

## 2. Proof-of-Restraint Invariant I-2 Audit

- **Read Operations**: `aios_model_endpoint_list` is pure query, requires zero capability tokens, and makes no filesystem or database mutations.
- **Mutation Operations**: `aios_model_endpoint_register` changes endpoint mappings and strictly requires a capability token grant.
- **Zero Escalation**: Confirmed across all test suites and runtime interfaces.
