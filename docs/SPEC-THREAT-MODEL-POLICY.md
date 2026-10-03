# Specification: Threat Model Security Policy (SPEC-THREAT-MODEL-POLICY)

- **Status**: APPROVED
- **Date**: 2026-10-03
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Threat Model Security Policy
- **Binding**: ADR-0035 §F-2, ADR-0036 §B-1

## 1. Overview
The Threat Model Security Policy subsystem establishes declarative governance over threat entry registration, lifecycle status transitions, mitigation requirements, and catalog-wide risk ceilings across the AIOS kernel.

## 2. Policy Schema

```json
{
  "version": "1.0.0",
  "mode": "enforcing",
  "require_cwe_mapping": true,
  "disallow_unmitigated_critical": true,
  "prohibited_categories": [],
  "max_catalog_threats": 512,
  "max_critical_threats": 16,
  "allow_canonical_override": false
}
```

## 3. Data Models

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatPolicyMode {
    Enforcing,
    Permissive,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum ThreatPolicyVerdict {
    Permit,
    PermitWithWarning { warning: String },
    Deny { reason: String, code: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatModelSecurityPolicy {
    pub version: String,
    pub mode: ThreatPolicyMode,
    pub require_cwe_mapping: bool,
    pub disallow_unmitigated_critical: bool,
    pub prohibited_categories: Vec<ThreatCategory>,
    pub max_catalog_threats: usize,
    pub max_critical_threats: usize,
    pub allow_canonical_override: bool,
}
```

## 4. Invariants & Rulesets

| Invariant | Name | Description |
|:---|:---|:---|
| `THREATPOL1` | **Version Conformance** | `version` must be non-empty and start with `"1."`. |
| `THREATPOL2` | **Mode Gating** | In `Enforcing` mode, violations yield `Deny`. In `Permissive` mode, violations yield `PermitWithWarning`. In `Disabled`, all checks yield `Permit`. |
| `THREATPOL3` | **CWE Mapping Enforcement** | If `require_cwe_mapping` is true, entries without CWE IDs are rejected (`THREATPOL_ERR_CWE_REQUIRED`). |
| `THREATPOL4` | **Critical Unmitigated Guard** | If `disallow_unmitigated_critical` is true, Critical severity threats cannot be transitioned to `Accepted` or `Resolved` without mitigations (`THREATPOL_ERR_CRITICAL_UNMITIGATED`). |
| `THREATPOL5` | **Prohibited Categories** | Threat entries matching any category in `prohibited_categories` are rejected (`THREATPOL_ERR_CATEGORY_PROHIBITED`). |
| `THREATPOL6` | **Capacity & Density Limits** | Catalog size cannot exceed `max_catalog_threats` and unmitigated critical count cannot exceed `max_critical_threats`. |
| `THREATPOL7` | **Atomic Persistence & Bounded Storage** | Policy files must not exceed 64 KiB (`MAX_THREAT_SECURITY_POLICY_BYTES = 65_536`), symlinks are rejected, and writes are atomic. |

## 5. Evaluation API

```rust
impl ThreatModelSecurityPolicy {
    pub fn evaluate_registration(&self, entry: &ThreatEntry) -> ThreatPolicyVerdict;
    pub fn evaluate_transition(&self, entry: &ThreatEntry, next_status: ThreatStatus) -> ThreatPolicyVerdict;
    pub fn evaluate_mitigation(&self, entry: &ThreatEntry, mitigation: &str) -> ThreatPolicyVerdict;
    pub fn evaluate_assessment(&self, assessment: &ThreatRiskAssessment) -> ThreatPolicyVerdict;
    pub fn load_from_path<P: AsRef<Path>>(path: P) -> Result<Self, String>;
    pub fn save_to_path<P: AsRef<Path>>(&self, path: P) -> Result<(), String>;
}
```

## 6. MCP Production Integration
Exposed as tool `aios.threat.policy`:
- `action: "show"`: Returns the active security policy configuration.
- `action: "evaluate_threat"`: Evaluates a threat entry or transition against the policy and returns verdict (`permit`, `permit_with_warning`, or `deny`).
