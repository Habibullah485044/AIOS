# Specification & Operator Guide: Threat Model Maintenance Store Recovery & Integrity Validation (SPEC-THREAT-MODEL-RECOVERY)

- **Status**: IMPLEMENTED & VERIFIED
- **Date**: 2026-10-04
- **Scope**: Catalog integrity verification, corruption quarantine, automated backup snapshotting, and non-destructive self-healing recovery for Threat Model Maintenance.

## 1. Overview
The Threat Model Recovery subsystem safeguards the threat catalog (`threats.json`) against crashes, partial writes, corrupted serialization, and storage failures. It provides non-destructive inspection, atomic repairs, timestamped quarantine preserving bad data, and snapshot restoration.

## 2. Operator Usage & Code Examples

### 2.1 Rust API Usage

```rust
use std::path::Path;
use aiosh_core::threat_model_recovery::{ThreatRecoveryService, ThreatCatalogStatus};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let catalog_path = Path::new("docs/threat_model.json");

    // 1. Non-destructively inspect catalog integrity
    let report = ThreatRecoveryService::verify_integrity(catalog_path);
    println!("Store status: {:?}, Total threats: {}", report.status, report.total_threats);

    if report.status != ThreatCatalogStatus::Healthy {
        // 2. Perform automated repair
        let recovery = ThreatRecoveryService::repair_catalog(catalog_path)?;
        println!("Recovered {} entries. Quarantined file: {:?}", 
            recovery.threats_recovered, recovery.quarantined_path);
    }

    // 3. Create backup snapshot
    let backup_path = ThreatRecoveryService::create_backup(catalog_path)?;
    println!("Backup written to: {}", backup_path.display());

    Ok(())
}
```

### 2.2 Integration via `ThreatModelService`

```rust
use std::path::Path;
use aiosh_core::threat_model_service::ThreatModelService;

let path = Path::new("docs/threat_model.json");
let integrity = ThreatModelService::verify_integrity(path);
if !integrity.issues.is_empty() {
    let result = ThreatModelService::repair_store(path).expect("repair succeeded");
    println!("Repaired catalog: threats recovered = {}", result.threats_recovered);
}
```

## 3. Invariants & Security Guarantees
- `THREATREC1` (**Non-Destructive Verification**): `verify_integrity` performs read-only checks without side effects.
- `THREATREC2` (**Deterministic Backup**): `create_backup` produces `<path>.bak` snapshots.
- `THREATREC3` (**Quarantine Preservation**): Corrupted catalogs are quarantined with unique timestamped filenames (`.corrupt.{pid}.{nanos}`) before salvage/repair.
- `THREATREC4` (**Path Traversal Rejection**): Path traversals (`..`), UNC paths, control characters, and symlinks are strictly rejected (`THREATREC_ERR_PATH_TRAVERSAL`).
- `THREATREC5` (**Safe Baseline Fallback**): Completely irreparable or missing catalogs safely reseed canonical STRIDE threat entries.

## 4. Constraints & Known Limitations
- Maximum store file size is hard-capped at 1 MiB (`MAX_THREAT_MODEL_STORE_SIZE`).
- Path depth cannot exceed 16 components.
- Automatic recovery salvages all entries matching valid schema constraints; malformed entries are quarantined and dropped from active catalog.

## 5. Evidence Artifacts
- Research: [T-02791 Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02791-recovery-research.md)
- Specification: [T-02792 Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02792-recovery-validation-specification.md)
- Scaffold: [T-02793 Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02793-recovery-validation-scaffold.md)
- Implementation: [T-02794 Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02794-recovery-validation-implementation.md)
- Unit Tests: [T-02795 Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02795-recovery-validation-unit-test.md)
- Integration: [T-02796 Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02796-recovery-validation-integration.md)
- Security Review: [T-02797 Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02797-recovery-validation-security-review.md)
- Hardening: [T-02798 Evidence](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02798-recovery-validation-hardening.md)
