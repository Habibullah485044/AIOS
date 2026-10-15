# Research: Security Policy for Incident Response Runbooks (T-03023)

**Task ID**: T-03023 (Phase 2 — Security Kernel & PEP Fabric / Incident Response Runbooks / security policy: Research)  
**Contract Reference**: `ADR-0035`, `ADR-0036`, `docs/SPEC-INCIDENT-RUNBOOK-CONFIG.md`, NIST SP 800-61 Rev. 2, CISA Incident Response Guidelines  
**Date**: 2026-10-15  
**Author**: Codebuff (Antigravity Autonomous Pair)  
**Status**: COMPLETE — Facts, constraints, prior art, and architectural decisions established.

---

## 1. Authoritative Sources & Standards

1. **NIST SP 800-61 Rev. 2 ("Computer Security Incident Handling Guide")**:
   - Outlines four incident response lifecycle phases: (1) Preparation, (2) Detection & Analysis, (3) Containment, Eradication & Recovery, (4) Post-Incident Activity.
   - Section 3.2 emphasizes authorization barriers for destructive containment actions: network segmentation, account disabling, and process termination must prevent lateral adversary expansion without self-inflicted system degradation.
2. **AIOS Architectural Decision Records**:
   - `ADR-0035` §D-2: FastMCP as the singular model-facing tool protocol; fail-closed dispatch boundaries.
   - `ADR-0036` (Capability-based PEP & Attenuation): State-changing paths require capability redemption.
   - `ADR-0037` (Proof-of-Restraint): Destructive remediation commands require explicit human confirmation (Invariant I-2).
3. **Existing Subsystem Prior Art**:
   - `code/aiosh-rust/aiosh-core/src/pep_grant_security_policy.rs`: Standard policy lifecycle, 3-state enforcement modes (`Enforcing`, `Permissive`, `Disabled`), serialization bounds ($\le 64$ KiB).
   - `code/aiosh-rust/aiosh-core/src/threat_model_policy.rs`: Policy-driven rule matrices and structured violation reporting.

---

## 2. Facts vs Assumptions

### Established Facts
1. *Fact*: High-risk incident remediation steps (e.g. process killing, network dropping, token revocation) can cause denial-of-service if executed erroneously.
2. *Fact*: All state-changing incident response steps must emit an append-only row to SQLite `audit_ring` with `audit_id > 0`.
3. *Fact*: Invariant I-2 strictly mandates that steps marked `requires_confirmation = true` or `phase == Eradication` cannot proceed unattended.
4. *Fact*: Scanners (`scan_net`, `scan_files`, `scan_web`) consume sockets, CPU, and disk I/O, requiring explicit bounds enforced at the policy level.

### Explicit Assumptions
1. *Assumption*: The default enforcement mode must be `Enforcing` (fail-closed); operators can opt into `Permissive` (audit-only) during test simulations.
2. *Assumption*: Default max step timeout under policy should be 60 seconds (clamped within $[1, 300]$ seconds).
3. *Assumption*: Default maximum scan recursion depth is 16 levels; max ports scanned per session is 10,000.

---

## 3. Decisions Needed & Proposed Contract

| Decision | Proposed Policy Contract | Rationale |
|:---|:---|:---|
| **Enforcement Modes** | `Enforcing`, `Permissive`, `Disabled` | Conforms with `PepGrantSecurityPolicy` and standard AIOS policy conventions. |
| **Confirmation Gate Policy** | Mandatory operator confirmation for High/Critical severity and Eradication phase | Enforces Proof-of-Restraint (Invariant I-2). |
| **Substrate Allowlist** | Configurable `allowed_substrates` (Process, Network, Identity, AuditRing, Storage) | Prevents unapproved access to sensitive storage partitions during emergency response. |
| **Scan Budgeting** | Maximum concurrent ports $\le 65535$, recursion depth $\le 32$, max matches $\le 1000$ | Prevents local resource starvation during active incident investigation. |
| **Configuration Path** | `docs/runbook_policy.json` (max 64 KiB, utf-8) | Standardized schema and storage location. |

---

## 4. Unknowns & Next Steps
- None blocking. Ready to proceed to specification task `T-03024`.
