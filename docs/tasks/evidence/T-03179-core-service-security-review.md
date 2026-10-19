# Security Review: AI Control Plane Model Backend Adapters Core Service (T-03179)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / core service
- **Artifact**: `docs/tasks/evidence/T-03179-core-service-security-review.md`
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS-SERVICE
- **Review Date**: 2026-10-18

---

## 1. Threat Modeling & Abuse Scenarios

### Abuse Scenario 1: Unauthorized Model Inference & Capability Bypass
- **Threat Vector**: An unprivileged agent attempts to execute Large Language Model inference via `aios_model_complete` without possessing a valid Proof-of-Restraint capability token.
- **Impact**: Resource exhaustion, unmetered external LLM billing, bypass of constitutional auditing.
- **Analysis**: `aios_model_complete` enforces `if not capability_token or not capability_token.strip(): return {"ok": False, "error": "MODSERV_ERR_UNAUTHORIZED..."}` fail-closed prior to dispatching any network or compute workload.
- **Verdict**: **SAFE / MITIGATED** (Enforces PoR Invariant I-2).

### Abuse Scenario 2: Plaintext Credential Exfiltration in Error Payloads
- **Threat Vector**: An external provider returns an HTTP 401/403 or connection failure detailing the Authorization header or API token; this error is reflected to callers or recorded in unencrypted audit logs.
- **Impact**: Permanent compromise of production API credentials (`sk-...`, `ghp_...`).
- **Analysis**: All exceptions raised within `complete()` and FastMCP tool wrappers pass through `redact_secrets()`, which scrubs regex `(?:Bearer\s+[a-zA-Z0-9_\-\.]+|sk-[a-zA-Z0-9_\-]{10,}|ghp_[a-zA-Z0-9_\-]{10,})` replacing matches with `[REDACTED_SECRET]`.
- **Verdict**: **SAFE / MITIGATED**.

### Abuse Scenario 3: Fallback Loop Amplification & Denial of Service
- **Threat Vector**: An attacker supplies cyclic or duplicate fallback backends (`fallback_backends=["backend-a", "backend-a", "backend-a"]`), multiplying latency and exhausting socket pools.
- **Impact**: Service hang, thread starvation, denial of service.
- **Analysis**: `complete()` constructs `chain = [request.model_id]` and deduplicates entries (`[b for b in fallback_backends if b != request.model_id]`). However, duplicate entries inside `fallback_backends` itself can be further hardened with a `seen` set and bounded chain length.
- **Recommendation**: Implement `MAX_FALLBACK_DEPTH = 5` and strict deduplication in Hardening (T-03180).

### Abuse Scenario 4: Oversized Request Payloads & Memory Exhaustion
- **Threat Vector**: Malicious agent sends tens of thousands of messages or gigabytes of prompt content to consume server RAM.
- **Impact**: Out-of-memory crash of FastMCP daemon.
- **Analysis**: `ModelMessage` bounds individual message payloads to 1 MiB (`MAX_MESSAGE_BYTES`), and `ModelRequest.validate()` verifies message list is non-empty and bounded.
- **Verdict**: **SAFE / MITIGATED**.

### Abuse Scenario 5: SSRF via Custom Backend Endpoints
- **Threat Vector**: An attacker registers or modifies a backend with internal cloud metadata URLs (`http://169.254.169.254/latest/meta-data/`) or forbidden local schemes (`file://`).
- **Impact**: Cloud IAM credential extraction, local filesystem disclosure.
- **Analysis**: `ModelEndpointConfig.validate()` restricts schemes strictly to `http://`, `https://`, `ws://`, or `wss://` and forbids ASCII control characters.
- **Verdict**: **SAFE / MITIGATED**.

---

## 2. Hardening Directives for T-03180

1. Deduplicate `fallback_backends` while preserving order and clamp total chain length to `MAX_FALLBACK_DEPTH = 5`.
2. Bound total conversation message count in `ModelRequest` to `MAX_REQUEST_MESSAGES = 100`.
3. Ensure all error paths strictly redact secrets and enforce bounds.
