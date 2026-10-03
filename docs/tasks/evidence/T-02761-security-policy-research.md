# Research: Threat Model Security Policy (T-02761)

## 1. Executive Summary & Objective
This research establishes the facts, constraints, authoritative sources, and architecture for the Threat Model Security Policy subsystem (`T-02761`..`T-02770`). It defines declarative governance rules, policy modes (`Enforcing`, `Permissive`, `Disabled`), policy evaluation verdicts (`Permit`, `PermitWithWarning`, `Deny`), and boundary conditions for threat registration, state transitions, and mitigation attachment.

## 2. Authoritative Citations & Standards
- **NIST SP 800-53 Rev. 5**: *Security and Privacy Controls for Information Systems and Organizations*. RA-3 (Risk Assessment), CA-7 (Continuous Monitoring), SA-11 (Developer Testing and Evaluation). Mandates formal policy enforcement on threat tracking and unmitigated risk acceptance.
- **ADR-0035**: PEP Fabric, Audit Ring, and Policy Evaluation Gates. Requires policy evaluation at PEP enforcement boundaries with immutable audit rows.
- **ADR-0036**: Security Architecture Invariant Rulesets (`THREATPOL1`..`THREATPOL6`).
- **NIST SP 800-154**: *Guide to Data-Centric System Threat Modeling*. Prohibits silent acceptance of critical unmitigated vulnerabilities without cryptographic authorization.
- **CWE-862 / CWE-863**: Missing / Incorrect Authorization.

## 3. Fact vs. Assumption Separation

| Item | Status | Details |
|---|---|---|
| Policy Modes | **Fact** | All AIOS security policies (`secret_policy.rs`, `privilege_policy.rs`) use `Enforcing`, `Permissive`, and `Disabled` modes. |
| Policy Verdicts | **Fact** | Returns `Permit`, `PermitWithWarning { warning }`, or `Deny { reason, code }`. |
| Unmitigated Critical Threats | **Fact** | Critical threats must not be accepted or resolved without documented mitigations under default enforcing policy. |
| CWE Mapping Enforcement | **Fact** | Enterprise policy requires every registered threat to link at least one valid CWE identifier. |
| Persistence & Limits | **Fact** | Policy files capped at 64 KiB (`MAX_THREAT_SECURITY_POLICY_BYTES = 65_536`), symlinks rejected, atomic file rename. |
| Service Integration | **Assumption** | `ThreatModelService` can accept an optional or configured `ThreatModelSecurityPolicy` to gate mutations. |

## 4. Policy Invariants (THREATPOL1..THREATPOL6)
1. **`THREATPOL1` (Version Conformance)**: Policy version must be non-empty and start with `"1."`.
2. **`THREATPOL2` (Mode Gating)**: In `Enforcing` mode, violations return `Deny`; in `Permissive`, violations return `PermitWithWarning`; in `Disabled`, checks pass unconditionally.
3. **`THREATPOL3` (CWE Requirement)**: When `require_cwe_mapping` is true, entries without CWE IDs are rejected.
4. **`THREATPOL4` (Critical Unmitigated Guard)**: When `disallow_unmitigated_critical` is true, Critical severity threats cannot be transitioned to `Accepted` or `Resolved` without mitigations.
5. **`THREATPOL5` (Prohibited Categories)**: Any threat matching `prohibited_categories` is rejected.
6. **`THREATPOL6` (Atomic Persistence & Bounded Size)**: Policy files capped at 64 KiB, symlinks rejected, atomic save.

## 5. Decisions Needed & Explicit Choices
- **Decision 1**: Define `ThreatModelSecurityPolicy` in `code/aiosh-rust/aiosh-core/src/threat_model_policy.rs`.
- **Decision 2**: Integrate into `aiosh-mcp` with an MCP tool `aios.threat.policy` for inspecting and evaluating policy verdicts.
- **Decision 3**: No external dependencies required; utilize existing `serde` and `aiosh-core` primitives.
