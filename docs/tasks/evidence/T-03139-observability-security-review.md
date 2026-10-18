# Security Review & Proof-of-Restraint Evidence: MCP Server Core Observability (T-03139)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / observability
- **Target**: Security review, threat modeling, abuse scenarios, and PoR Invariant I-2 compliance
- **Bindings**: SPEC-MCP-SERVER-CORE-OBSERVABILITY, ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2

---

## 1. Threat Model & Abuse Scenario Matrix

| Scenario ID | Attack Vector / Abuse Pattern | Target Layer | Mitigation / Enforcement Mechanism | Status |
|:---|:---|:---|:---|:---|
| **AS-OBS-1** | Sensitive Data / Secret Leakage via Telemetry | Metrics Serializer | Telemetry records strictly high-level counts, percentages, and latency floats; no arguments, payloads, or capability tokens are included. | **MITIGATED** |
| **AS-OBS-2** | Memory Exhaustion via Metric Accumulation | Collector Engine | O(1) constant-space storage: running counts and cumulative durations; no unbounded in-memory list allocations. | **MITIGATED** |
| **AS-OBS-3** | Covert State Mutation via Snapshot API | FastMCP Tool | Pure read-only endpoint (`aios_mcp_observability_snapshot`); accepts zero state-altering parameters. | **MITIGATED** |
| **AS-OBS-4** | NaN / Division-by-Zero Serialization Poisoning | Metrics Math | Guarded zero checks for dispatch count and session capacity; all computed floats guaranteed finite. | **MITIGATED** |
| **AS-OBS-5** | Capability Gating Bypass (PoR Invariant I-2) | Privilege Enforcement | Observability queries are classified as `READ_ONLY`; they cannot mint tokens or execute consequential actions. | **MITIGATED** |

---

## 2. Proof-of-Restraint Verification (Invariant I-2)

- **Standing Rule Check**: Confirmed that the observability subsystem is strictly read-only and does not touch or expose any state-changing dispatch path.
- **Audit Ring Invariant**: Reading metrics does not circumvent WAL audit logging; health and diagnostic queries remain fully auditable.
- **Invariant I-2 Status**: Verified. No security policy bypasses remain open.
