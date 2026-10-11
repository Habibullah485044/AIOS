# Research: Compliance Mapping Security Policy (T-02923)

## 1. Executive Summary & Objective
This research establishes the facts, constraints, authoritative sources, and architecture for the Compliance Mapping Security Policy subsystem (`T-02923`..`T-02932`). It defines declarative governance rules, policy modes (`Enforcing`, `Permissive`, `Disabled`), policy evaluation verdicts (`Permit`, `PermitWithWarning`, `Deny`), and invariant boundary conditions for compliance control mapping registration, status transitions (e.g. NonCompliant -> Compliant), baseline assessments, framework coverage, and audit emission.

## 2. Authoritative Citations & Standards
- **NIST SP 800-53 Rev. 5**: *Security and Privacy Controls for Information Systems and Organizations*.
  - CA-2 (Control Assessments): Requires formal policy enforcement and evidence validation before controls can be marked compliant.
  - CA-7 (Continuous Monitoring): Mandates monitoring of status shifts and detection of unapproved compliance assertions.
  - CM-2 (Baseline Configuration): Governs policy configuration immutability and version control.
  - SA-11 (Developer Testing and Evaluation): Requires automated policy verification across development lifecycle.
- **SOC 2 (2017 Trust Services Criteria)**:
  - CC6.1 / CC6.8: Requires authorization gates on compliance state alterations and integrity verification.
  - CC7.2: Continuous compliance monitoring and anomaly alerting.
- **ISO/IEC 27001:2022**:
  - Clause 9.1: Monitoring, measurement, analysis and evaluation.
  - Clause 9.2: Internal audit and control attestation verification.
  - Annex A Control 8.16: Monitoring activities and administrative integrity.
- **EU AI Act (Regulation 2024/1689)**:
  - Article 9: Continuous risk management and compliance tracking for AI systems.
  - Article 12 & Article 14: Automated record-keeping and human-in-the-loop oversight for high-risk systems.
- **ADR-0035 & ADR-0036**:
  - PEP Fabric, Audit Ring, and Policy Evaluation Gates. Requires policy evaluation at PEP enforcement boundaries with immutable audit rows.
  - Proof-of-Restraint Invariant I-2: Any state mutation (mint, update, transition) must require redemption of a cryptographic capability token.

## 3. Fact vs. Assumption Separation

| Item | Status | Details |
|---|---|---|
| Policy Modes | **Fact** | All AIOS security policies (`threat_model_policy.rs`, `privilege_policy.rs`, `secret_policy.rs`) use `Enforcing`, `Permissive`, and `Disabled` modes. |
| Policy Verdicts | **Fact** | Returns `Permit`, `PermitWithWarning { warning }`, or `Deny { reason, code }`. |
| Unmitigated / Non-Mitigated Controls | **Fact** | Marking controls as `compliant` strictly requires evidence or mitigation summaries; empty rationale must fail-closed under `Enforcing` mode. |
| Threat Mapping Requirement | **Fact** | Compliance mappings in regulated frameworks (NIST/SOC2) require at least one linked threat ID or reason when strict threat linking is enabled. |
| Supported Framework Whitelist | **Fact** | Enterprise security policies restrict compliance registrations to permitted compliance frameworks (`nist_sp_800_53`, `soc2_type2`, `iso_27001`, `eu_ai_act`, `custom`). |
| Minimum Compliance Threshold | **Fact** | Policy can mandate minimum compliant ratio threshold (e.g. 80.0%) for system assessment approvals. |
| Persistence & Limits | **Fact** | Policy config capped at 64 KiB (`MAX_COMPLIANCE_SECURITY_POLICY_BYTES = 65_536`), symlinks rejected, atomic file rename. |
| Service Integration | **Assumption** | `ComplianceMappingService` and MCP layer `aios_mcp` can integrate policy evaluation directly or as a gating layer. |

## 4. Policy Invariants (COMPLIANCEPOL1..COMPLIANCEPOL7)
1. **`COMPLIANCEPOL1` (Version Conformance)**: Policy version must be non-empty and start with `"1."`.
2. **`COMPLIANCEPOL2` (Mode Gating)**: In `Enforcing` mode, violations return `Deny`; in `Permissive`, violations emit `PermitWithWarning`; in `Disabled`, checks pass unconditionally.
3. **`COMPLIANCEPOL3` (Evidence & Mitigation Requirement)**: Transition to `Compliant` status requires non-empty `mitigation_summary` or `reason` (minimum 3 characters).
4. **`COMPLIANCEPOL4` (Permitted Frameworks)**: Control registration must belong to configured `permitted_frameworks` list if the list is non-empty.
5. **`COMPLIANCEPOL5` (Strict Threat Linkage)**: When `require_threat_linkage` is true, entries with zero associated threats are rejected.
6. **`COMPLIANCEPOL6` (Threshold Enforcement)**: Assessments falling below `min_compliant_percentage` fail policy evaluation in `evaluate_assessment`.
7. **`COMPLIANCEPOL7` (Atomic Persistence & Bounded Size)**: Config files capped at 64 KiB, symlinks rejected, atomic temporary file replacement.

## 5. Decisions Needed & Explicit Choices
- **Decision 1 (Location)**: Implement Rust security policy module at `code/aiosh-rust/aiosh-core/src/compliance_policy.rs` and export via `lib.rs`.
- **Decision 2 (Python / MCP Integration)**: Expose policy evaluation helper in `code/aiosh-mcp/aiosh_mcp/compliance_policy.py` and MCP tool/status commands.
- **Decision 3 (Dependencies)**: Pure standard library + `serde` / `serde_json`; zero external crates.
- **Decision 4 (Error Codes)**: Standard error prefixes `COMPLIANCEPOL_ERR_*` matching existing AIOS security kernel patterns.
