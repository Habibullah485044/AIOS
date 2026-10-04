# Specification: Compliance Mapping Data Model (SPEC-COMPLIANCE-DATA-MODEL)

- **Status**: APPROVED
- **Date**: 2026-10-04
- **Scope**: Data structures, standards taxonomy, bounds enforcement, and lifecycle state machines for Compliance Mapping.

## 1. Domain Constants & Error Codes

```rust
pub const MAX_COMPLIANCE_ID_LEN: usize = 64;
pub const MAX_COMPLIANCE_TITLE_LEN: usize = 128;
pub const MAX_COMPLIANCE_DESC_LEN: usize = 2048;
pub const MAX_COMPLIANCE_NOTES_LEN: usize = 2048;
pub const MAX_THREAT_IDS_COUNT: usize = 16;
pub const MAX_TAGS_COUNT: usize = 16;
pub const MAX_COMPLIANCE_ENTRIES_CAPACITY: usize = 1024;

pub const COMPLIANCE_ERR_INVALID_ID: &str = "COMPLIANCE_ERR_INVALID_ID";
pub const COMPLIANCE_ERR_INVALID_TITLE: &str = "COMPLIANCE_ERR_INVALID_TITLE";
pub const COMPLIANCE_ERR_BOUNDS_EXCEEDED: &str = "COMPLIANCE_ERR_BOUNDS_EXCEEDED";
pub const COMPLIANCE_ERR_CONTROL_CHARS: &str = "COMPLIANCE_ERR_CONTROL_CHARS";
pub const COMPLIANCE_ERR_DUPLICATE_ID: &str = "COMPLIANCE_ERR_DUPLICATE_ID";
pub const COMPLIANCE_ERR_INVALID_STATUS_TRANSITION: &str = "COMPLIANCE_ERR_INVALID_STATUS_TRANSITION";
pub const COMPLIANCE_ERR_MISSING_SUBSTRATE_REF: &str = "COMPLIANCE_ERR_MISSING_SUBSTRATE_REF";
```

## 2. Enumerations

### 2.1 Compliance Frameworks
```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceFramework {
    NistSp80053Rev5,
    Soc2Type2,
    Iso27001,
    CisControlsV8,
    HipaaSecurity,
    PciDssV4,
}
```

### 2.2 Compliance Status
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceStatus {
    Compliant,
    PartiallyCompliant,
    NonCompliant,
    NotApplicable,
}
```

### 2.3 Substrate Target Binding
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubstrateTargetType {
    PepGate,
    CapabilityToken,
    AuditRing,
    ThreatMitigation,
    ConstitutionRule,
}
```

## 3. Data Structures

### 3.1 `ComplianceControl`
Represents an individual standard requirement (e.g., NIST AC-3 or SOC 2 CC6.1).

### 3.2 `ComplianceMappingEntry`
Represents a mapped relationship between an external compliance requirement and an internal AIOS enforcement primitive (PEP gate, capability, threat mitigation).

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceMappingEntry {
    pub id: String,
    pub control_id: String,
    pub framework: ComplianceFramework,
    pub target_type: SubstrateTargetType,
    pub target_ref: String,
    pub threat_ids: Vec<String>,
    pub status: ComplianceStatus,
    pub mitigation_summary: String,
    pub tags: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}
```

### 3.3 `ComplianceCatalogSnapshot`
Canonical container representing the complete mapping repository.

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceCatalogSnapshot {
    pub version: String,
    pub mappings: Vec<ComplianceMappingEntry>,
    pub generated_at: String,
}
```

## 4. Invariants Enforced
- `COMPLY1`: Normalized IDs (alphanumeric, dashes, underscores).
- `COMPLY2`: Substrate binding must be valid and non-empty.
- `COMPLY3`: Status transitions to `Compliant` validate mitigation presence.
- `COMPLY4`: Strict payload limits prevent denial of service (CWE-400).
- `COMPLY5`: Built-in canonical mappings available out of the box.
