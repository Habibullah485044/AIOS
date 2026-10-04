# Specification: Compliance Mapping Core Service (SPEC-COMPLIANCE-SERVICE)

- **Status**: APPROVED
- **Date**: 2026-10-04
- **Scope**: Runtime service engine, persistence, assessment reporting, and PEP integration for Compliance Mapping.

## 1. Constants & Error Codes

```rust
pub const DEFAULT_COMPLIANCE_MAP_PATH: &str = "docs/compliance_map.json";
pub const MAX_COMPLIANCE_STORE_SIZE: u64 = 1024 * 1024; // 1 MiB

pub const COMPLIANCESVC_ERR_NOT_FOUND: &str = "COMPLIANCESVC_ERR_NOT_FOUND";
pub const COMPLIANCESVC_ERR_CAPACITY_EXCEEDED: &str = "COMPLIANCESVC_ERR_CAPACITY_EXCEEDED";
pub const COMPLIANCESVC_ERR_FILE_SIZE: &str = "COMPLIANCESVC_ERR_FILE_SIZE";
pub const COMPLIANCESVC_ERR_PATH_TRAVERSAL: &str = "COMPLIANCESVC_ERR_PATH_TRAVERSAL";
pub const COMPLIANCESVC_ERR_IO: &str = "COMPLIANCESVC_ERR_IO";
pub const COMPLIANCESVC_ERR_PARSE: &str = "COMPLIANCESVC_ERR_PARSE";
```

## 2. Assessment Model: `ComplianceAssessmentReport`

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComplianceAssessmentReport {
    pub total_mappings: usize,
    pub compliant_count: usize,
    pub partially_compliant_count: usize,
    pub non_compliant_count: usize,
    pub not_applicable_count: usize,
    pub compliance_percentage: f64,
    pub gap_control_ids: Vec<String>,
    pub evaluated_at: String,
}
```

## 3. Service Interface: `ComplianceService`

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplianceService {
    pub snapshot: ComplianceCatalogSnapshot,
}

impl ComplianceService {
    pub fn new() -> Self;
    pub fn with_canonical_baseline() -> Self;
    pub fn validate_path(path: &Path) -> Result<PathBuf, String>;
    pub fn load_from_path(path: &Path) -> Result<Self, String>;
    pub fn save_to_path(&self, path: &Path) -> Result<(), String>;
    pub fn register_mapping(&mut self, entry: ComplianceMappingEntry) -> Result<(), String>;
    pub fn update_status(&mut self, id: &str, status: ComplianceStatus, reason: &str) -> Result<(), String>;
    pub fn assess_framework(&self, framework: Option<ComplianceFramework>) -> ComplianceAssessmentReport;
    pub fn verify_pep_coverage(&self, gate_id: &str) -> bool;
}
```

## 4. Invariants & Security Mandates
- **COMPLYSVC1 (Side-Effect-Free Assessment)**: Queries and evaluations are strictly non-mutating.
- **COMPLYSVC2 (Crash-Consistent Persistence)**: Writes execute via atomic rename using PID/nanosecond-tagged temporary files.
- **COMPLYSVC3 (Path Sanitization)**: Path traversals, UNC roots, control characters, and symlinks are strictly rejected.
- **COMPLYSVC4 (Resource Bounds)**: Stores capped at 1 MiB (`MAX_COMPLIANCE_STORE_SIZE`).
- **COMPLYSVC5 (Deterministic Auditing)**: Quantitative scoring of compliance coverage and gap identification.
