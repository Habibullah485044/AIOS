# Specification Evidence: Threat Model Maintenance Recovery & Validation (T-02792)

- **Task ID**: T-02792
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Threat Model Maintenance / recovery & validation
- **Status**: Completed
- **Document Date**: 2026-10-04

## 1. Specification Overview
The specification defines the formal API contracts, data types, error enumerations, and persistence behaviors for the Threat Model Recovery & Integrity Validation subsystem.

### Inputs and Outputs
- `verify_integrity(path: &Path) -> ThreatIntegrityReport`:
  - Input: Path to threat model JSON file.
  - Output: `ThreatIntegrityReport` detailing status (`Healthy`, `Degraded`, `Corrupted`, `Missing`), list of issues, total threat entries, valid/corrupted counts, backup existence.
- `create_backup(path: &Path) -> Result<PathBuf, String>`:
  - Input: Path to active threat model file.
  - Output: Path to generated `.bak` backup file.
- `repair_catalog(path: &Path) -> Result<ThreatRecoveryReport, String>`:
  - Input: Path to damaged threat model file.
  - Output: `ThreatRecoveryReport` indicating actions performed, recovered entries, quarantined file path, and success status.
- `restore_from_backup(path: &Path) -> Result<ThreatRecoveryReport, String>`:
  - Input: Path to target threat model file.
  - Output: `ThreatRecoveryReport` restoring catalog state from `<path>.bak`.

## 2. Invariants
- `THREATREC1`: Non-destructive read-only verification.
- `THREATREC2`: Bounded backup snapshotting before mutation.
- `THREATREC3`: Quarantine preservation using timestamped `.corrupt.<nanos>` files.
- `THREATREC4`: Strict path validation (CWE-22, CWE-59 rejection).
- `THREATREC5`: Safe canonical STRIDE baseline fallback.

## 3. Interface Reuse & New Interfaces
- **Reused**:
  - `ThreatEntry`, `ThreatModelSnapshot` from `threat_model_data_model.rs`.
  - `ThreatModelService` from `threat_model_service.rs`.
  - `utcnow_iso` from `canonical.rs`.
- **New (AIOS-specific)**:
  - `ThreatCatalogStatus`, `ThreatIssueSeverity`, `ThreatIssueType`.
  - `ThreatIntegrityIssue`, `ThreatIntegrityReport`.
  - `ThreatRecoveryAction`, `ThreatRecoveryReport`.
  - `ThreatRecoveryService`.
