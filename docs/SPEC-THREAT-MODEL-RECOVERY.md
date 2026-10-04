# Specification: Threat Model Maintenance Store Recovery & Integrity Validation (SPEC-THREAT-MODEL-RECOVERY)

- **Status**: APPROVED
- **Date**: 2026-10-04
- **Scope**: Catalog integrity verification, corruption quarantine, automated backup snapshotting, and non-destructive self-healing recovery for Threat Model Maintenance.

## 1. Data Contracts

### 1.1 Issue Severity & Types
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatCatalogStatus {
    Healthy,
    Degraded,
    Corrupted,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatIssueSeverity {
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatIssueType {
    MissingCatalogFile,
    InvalidJsonSyntax,
    SchemaMismatch,
    CorruptedEntry,
    DuplicateThreatId,
    OversizedPayload,
    SymlinkForbidden,
    InvalidPathTraversal,
    InvalidTimestamp,
}
```

### 1.2 Diagnostic & Recovery Models
```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatIntegrityIssue {
    pub severity: ThreatIssueSeverity,
    pub issue_type: ThreatIssueType,
    pub threat_id: Option<String>,
    pub details: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatIntegrityReport {
    pub store_path: String,
    pub status: ThreatCatalogStatus,
    pub total_threats: usize,
    pub valid_threats: usize,
    pub corrupted_threats: usize,
    pub issues: Vec<ThreatIntegrityIssue>,
    pub has_backup: bool,
    pub backup_path: Option<String>,
    pub timestamp: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatRecoveryAction {
    pub action_type: String,
    pub target_id: Option<String>,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatRecoveryReport {
    pub store_path: String,
    pub success: bool,
    pub actions: Vec<ThreatRecoveryAction>,
    pub threats_recovered: usize,
    pub threats_dropped: usize,
    pub quarantined_path: Option<String>,
    pub timestamp: String,
}
```

## 2. Service Interface: `ThreatRecoveryService`

```rust
pub struct ThreatRecoveryService;

impl ThreatRecoveryService {
    /// Validates path against directory traversal, control characters, and symlinks.
    pub fn validate_path(path: &Path) -> Result<PathBuf, String>;

    /// Derives standard backup path `<path>.bak`.
    pub fn backup_path_for(path: &Path) -> PathBuf;

    /// Derives quarantine path `<path>.corrupt.<nanos>`.
    pub fn quarantine_path_for(path: &Path) -> PathBuf;

    /// Creates backup snapshot of threat catalog.
    pub fn create_backup(path: &Path) -> Result<PathBuf, String>;

    /// Non-destructively verifies catalog integrity.
    pub fn verify_integrity(path: &Path) -> ThreatIntegrityReport;

    /// Repairs corrupted catalog, salvaging valid entries, quarantining corrupt source.
    pub fn repair_catalog(path: &Path) -> Result<ThreatRecoveryReport, String>;

    /// Restores catalog from `.bak` backup file.
    pub fn restore_from_backup(path: &Path) -> Result<ThreatRecoveryReport, String>;
}
```

## 3. Invariants & Security Mandates

- **THREATREC1 (Non-Destructive Verification)**: `verify_integrity` does not alter source files.
- **THREATREC2 (Deterministic Backup)**: `create_backup` writes atomically to `.bak` preserving original permissions.
- **THREATREC3 (Quarantine Preservation)**: Damaged catalogs are moved to `.corrupt.<nanos>` before salvage/repair.
- **THREATREC4 (Path Traversal / Device Rejection)**: `..`, control characters, UNC paths, and symlinks are strictly rejected.
- **THREATREC5 (Safe Baseline Fallback)**: If file is completely empty or missing, optionally seeds canonical STRIDE catalog.
