# Specification: Compliance Mapping Security Policy (SPEC-COMPLIANCE-SECURITY-POLICY)

- **Status**: IMPLEMENTED & HARDENED
- **Date**: 2026-10-11
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Compliance Mapping Security Policy
- **Binding**: NIST SP 800-53 Rev 5 (CA-2, CA-7, CM-2, SA-11), SOC 2 (CC6.1, CC6.8, CC7.2), ADR-0035, ADR-0036, PoR Invariant I-2
- **Tasks**: T-02923 (Research), T-02924 (Spec), T-02925 (Scaffold), T-02926 (Impl), T-02927 (Unit Test), T-02928 (Integration), T-02929 (Security Review), T-02930 (Hardening), T-02931 (Documentation), T-02932 (Verification)

---

## 1. Overview & Objectives

The Compliance Mapping Security Policy subsystem establishes declarative governance over the registration, lifecycle progression, framework attestation, and threshold auditing of security compliance controls.

It enforces fail-closed boundary controls preventing:
- Fraudulent attestation of unmitigated controls as `Compliant`.
- Pollution of compliance catalogs with unapproved regulatory frameworks.
- Registration of orphaned controls lacking threat traceability.
- Acceptance of sub-threshold system posture reports.
- Memory exhaustion and symlink traversal in policy configuration storage.

---

## 2. Policy Invariants (`COMPLIANCEPOL1`..`COMPLIANCEPOL7`)

| Invariant | Title | Rule & Behavioral Guarantee |
|---|---|---|
| **`COMPLIANCEPOL1`** | Version Conformance | Policy version must be non-empty, start with `"1."`, and not exceed 32 bytes. |
| **`COMPLIANCEPOL2`** | Mode Gating | `Enforcing`: violations return `Deny`; `Permissive`: violations return `PermitWithWarning`; `Disabled`: checks pass unconditionally. |
| **`COMPLIANCEPOL3`** | Mitigation on Compliant | Transitions to `Compliant` status strictly require documented mitigation summaries (minimum 3 non-whitespace characters); empty entries fail with `COMPLIANCEPOL_ERR_MITIGATION_REQUIRED`. |
| **`COMPLIANCEPOL4`** | Framework Whitelist | If `permitted_frameworks` is configured (non-empty), control registrations outside the whitelist are rejected with `COMPLIANCEPOL_ERR_FRAMEWORK_PROHIBITED`. |
| **`COMPLIANCEPOL5`** | Strict Threat Linkage | If `require_threat_linkage` is true, control mappings with empty `threat_ids` are rejected with `COMPLIANCEPOL_ERR_THREAT_REQUIRED`. |
| **`COMPLIANCEPOL6`** | Assessment Threshold | Assessments whose `compliance_percentage` falls below `min_compliant_percentage` fail evaluation with `COMPLIANCEPOL_ERR_THRESHOLD_UNMET`. |
| **`COMPLIANCEPOL7`** | Atomic Persistence & File Bounds | Policy file capped at 64 KiB (`MAX_COMPLIANCE_SECURITY_POLICY_BYTES = 65_536`). Symlinks rejected. Writes execute via process-isolated temp files and atomic rename. |

---

## 3. Schema & Type Contracts

### 3.1 Rust Types (`code/aiosh-rust/aiosh-core/src/compliance_policy.rs`)

```rust
pub const MAX_COMPLIANCE_SECURITY_POLICY_BYTES: u64 = 65_536; // 64 KiB

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompliancePolicyMode {
    Enforcing,
    Permissive,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum CompliancePolicyVerdict {
    Permit,
    PermitWithWarning { warning: String },
    Deny { reason: String, code: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComplianceSecurityPolicy {
    pub version: String,
    pub mode: CompliancePolicyMode,
    pub require_threat_linkage: bool,
    pub require_mitigation_on_compliant: bool,
    pub permitted_frameworks: Vec<ComplianceFramework>,
    pub min_compliant_percentage: f64,
    pub max_catalog_mappings: usize,
    pub allow_canonical_override: bool,
}
```

### 3.2 Python Types (`code/aiosh-mcp/aiosh_mcp/compliance_policy.py`)

```python
class CompliancePolicyMode(str, Enum):
    ENFORCING = "enforcing"
    PERMISSIVE = "permissive"
    DISABLED = "disabled"

@dataclass
class CompliancePolicyVerdict:
    verdict: str  # "permit", "permit_with_warning", "deny"
    warning: Optional[str] = None
    reason: Optional[str] = None
    code: Optional[str] = None

@dataclass
class ComplianceSecurityPolicy:
    version: str = "1.0.0"
    mode: CompliancePolicyMode = CompliancePolicyMode.ENFORCING
    require_threat_linkage: bool = True
    require_mitigation_on_compliant: bool = True
    permitted_frameworks: list[str] = field(default_factory=list)
    min_compliant_percentage: float = 80.0
    max_catalog_mappings: int = 1024
    allow_canonical_override: bool = False
```

---

## 4. Usage & Code Examples

### 4.1 Rust Service Integration

```rust
use aiosh_core::{
    ComplianceSecurityPolicy, ComplianceService, ComplianceStatus,
    ComplianceFramework, CompliancePolicyVerdict,
};

// Initialize service with canonical baseline and enforcing policy
let mut service = ComplianceService::with_canonical_baseline();
let policy = ComplianceSecurityPolicy::default();
service.set_policy(policy);

// Evaluate posture against 80% threshold
let (report, verdict) = service.assess_framework_with_policy(Some(ComplianceFramework::NistSp80053Rev5));
assert_eq!(verdict, CompliancePolicyVerdict::Permit);
println!("NIST Compliance: {:.1}% (Verdict: {:?})", report.compliance_percentage, verdict);
```

### 4.2 Python MCP Integration

```python
from aiosh_mcp.compliance import canonical_baseline, update_status
from aiosh_mcp.compliance_policy import ComplianceSecurityPolicy

snapshot = canonical_baseline()
policy = ComplianceSecurityPolicy(min_compliant_percentage=85.0)

# Updating status to compliant with mandatory mitigation rationale
entry = update_status(
    snapshot,
    id="MAP-NIST-AC3-PEP",
    status="compliant",
    reason="PEP gate kernel validation verified on syscall boundary",
    policy=policy,
)
print(f"Updated {entry.id} status to {entry.status}")
```

---

## 5. Error Code Matrix (`COMPLIANCEPOL_ERR_*`)

| Error Code | Trigger Condition |
|---|---|
| `COMPLIANCEPOL_ERR_VALIDATION` | Malformed policy fields (version not starting with `"1."`, bounds exceeded, NaN percentage). |
| `COMPLIANCEPOL_ERR_DENIED` | Generic fail-closed rejection under enforcing policy. |
| `COMPLIANCEPOL_ERR_THREAT_REQUIRED` | Control registered without at least one linked threat ID under strict threat policy. |
| `COMPLIANCEPOL_ERR_MITIGATION_REQUIRED` | Attempt to mark control `Compliant` with empty or short (< 3 chars) mitigation rationale. |
| `COMPLIANCEPOL_ERR_FRAMEWORK_PROHIBITED` | Attempt to register control under framework not permitted by enterprise policy whitelist. |
| `COMPLIANCEPOL_ERR_THRESHOLD_UNMET` | Assessed compliance percentage falls below `min_compliant_percentage`. |
| `COMPLIANCEPOL_ERR_CAPACITY_EXCEEDED` | Catalog entry count reaches `max_catalog_mappings`. |
| `COMPLIANCEPOL_ERR_OVERRIDE_FORBIDDEN` | Canonical baseline override attempted without explicit policy permission. |
| `COMPLIANCEPOL_ERR_IO` | File size > 64 KiB, symlinks rejected, or filesystem permission failures. |
| `COMPLIANCEPOL_ERR_PARSE` | Invalid JSON syntax during policy deserialization. |

---

## 6. Constraints & Known Limitations

1. **Pre-Read File Bound**: Policy configuration files are strictly capped at 64 KiB (`MAX_COMPLIANCE_SECURITY_POLICY_BYTES`). Larger configurations must be broken down or rejected.
2. **Symlink Rejection**: For CWE-59 defense, symlinks are unconditionally forbidden for policy JSON files.
3. **Threshold Precision**: Posture scores are calculated as `f64` ratios in percentage form (`0.0` .. `100.0`). Empty catalogs report `100.0%` by design.
4. **Proof-of-Restraint Gating**: State mutations through production CLI and MCP endpoints require prior capability token redemption (`cap:compliance:admin`).

---

## 7. Evidence & Audit Traceability

- Research: [T-02923-research.md](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02923-research.md)
- Specification: [T-02924-spec.md](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02924-spec.md)
- Scaffold: [T-02925-security-policy-scaffold.md](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02925-security-policy-scaffold.md)
- Implementation: [T-02926-security-policy-implementation.md](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02926-security-policy-implementation.md)
- Unit Tests: [T-02927-security-policy-unit-test.md](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02927-security-policy-unit-test.md)
- Integration: [T-02928-security-policy-integration.md](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02928-security-policy-integration.md)
- Security Review: [T-02929-security.md](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02929-security.md)
- Hardening: [T-02930-security-policy-hardening.md](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02930-security-policy-hardening.md)
