# Specification: Compliance Mapping Store Recovery & Integrity Validation (SPEC-COMPLIANCE-RECOVERY)

- **Status**: SPECIFIED
- **Date**: 2026-10-11
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Compliance Mapping Recovery & Validation
- **Binding**: ADR-0035 §I-1, ADR-0037 §D-1
- **Source Code**:
  - Rust: [`code/aiosh-rust/aiosh-core/src/compliance_recovery.rs`](../code/aiosh-rust/aiosh-core/src/compliance_recovery.rs)
  - Python: [`code/aiosh-mcp/aiosh_mcp/compliance_recovery.py`](../code/aiosh-mcp/aiosh_mcp/compliance_recovery.py)
  - MCP Tool: [`code/aiosh-mcp/aiosh_mcp/compliance.py`](../code/aiosh-mcp/aiosh_mcp/compliance.py)

---

## 1. Overview

The Compliance Mapping Recovery subsystem safeguards the regulatory compliance catalog (`docs/compliance_map.json`) against crashes, partial writes, corrupted serialization, and storage failures. It provides non-destructive inspection, atomic repairs, timestamped quarantine preserving damaged data, and snapshot restoration.

---

## 2. Data Types & Interfaces

```rust
pub const COMPLYREC_ERR_PATH_TRAVERSAL: &str = "COMPLYREC_ERR_PATH_TRAVERSAL";
pub const COMPLYREC_ERR_CORRUPT: &str = "COMPLYREC_ERR_CORRUPT";
pub const COMPLYREC_ERR_NO_BACKUP: &str = "COMPLYREC_ERR_NO_BACKUP";
pub const COMPLYREC_ERR_IO: &str = "COMPLYREC_ERR_IO";
pub const COMPLYREC_ERR_CAPACITY: &str = "COMPLYREC_ERR_CAPACITY";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceCatalogStatus {
    Healthy,
    Corrupt,
    Missing,
    CapacityExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceIntegrityReport {
    pub status: ComplianceCatalogStatus,
    pub file_path: String,
    pub total_mappings: usize,
    pub file_size_bytes: u64,
    pub is_valid: bool,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceRecoveryResult {
    pub success: bool,
    pub mappings_recovered: usize,
    pub quarantined_path: Option<String>,
    pub backup_path: Option<String>,
    pub message: String,
}

pub struct ComplianceRecoveryService;

impl ComplianceRecoveryService {
    pub fn verify_integrity(path: &Path) -> ComplianceIntegrityReport;
    pub fn create_backup(path: &Path) -> Result<PathBuf, String>;
    pub fn repair_catalog(path: &Path) -> Result<ComplianceRecoveryResult, String>;
    pub fn restore_from_backup(path: &Path) -> Result<ComplianceRecoveryResult, String>;
    pub fn validate_path(path: &Path) -> Result<PathBuf, String>;
}
```

---

## 3. Invariants & Security Guarantees

- `COMPLYREC1` (**Non-Destructive Verification**): `verify_integrity` performs read-only checks without mutating file contents or access times.
- `COMPLYREC2` (**Deterministic Backup**): `create_backup` produces `<path>.bak` snapshots via atomic temporary files.
- `COMPLYREC3` (**Quarantine Preservation**): Corrupted catalogs are quarantined with unique timestamped filenames (`<path>.corrupt.<pid>.<nanos>`) before salvage/repair.
- `COMPLYREC4` (**Path Traversal Rejection**): Path traversals (`..`), UNC paths, control characters, and symlinks are strictly rejected (`COMPLYREC_ERR_PATH_TRAVERSAL`).
- `COMPLYREC5` (**Safe Baseline Fallback**): Completely irreparable or missing catalogs safely reseed canonical compliance baselines.
- `PoR Invariant I-2`: `recovery-verify` is read-only (no grant needed); `recovery-backup`, `recovery-repair`, and `recovery-restore` require capability tokens under PEP gating.

---

## 4. MCP Surface Actions

Registered on tool `aios.compliance`:
- `action: "recovery-verify"`: Read-only inspection returning `ComplianceIntegrityReport`.
- `action: "recovery-backup"`: Writes snapshot backup `<path>.bak`.
- `action: "recovery-repair"`: Quarantines damaged store, salvages valid entries, or resets to canonical baseline.
- `action: "recovery-restore"`: Restores live store from `<path>.bak`.
