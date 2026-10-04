# Research Document: Threat Model Recovery & Validation (T-02791)

- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Threat Model Recovery & Validation
- **Focus**: Integrity Verification, Automated Snapshots, Crash Repair, and Quarantine Mechanics
- **Bindings**: ADR-0035 §I-1, ADR-0036 §E-1

## 1. Executive Summary
The Threat Model Recovery & Validation subsystem provides disaster recovery, structural verification, corruption quarantine, and snapshot restoration for the threat catalog persistence file (`threats.json`). In the event of process crashes, power failures, storage degradation, or malicious tampering, this subsystem enables automated discovery of invalid records, isolates damaged inputs into quarantine storage, restores known-good `.bak` snapshots, or falls back safely to canonical STRIDE baselines without compromising security invariants.

## 2. Invariants & Recovery Requirements

| Invariant | Name | Description |
|:---|:---|:---|
| `THREATREC1` | **Non-Destructive Integrity Verification** | `verify_integrity` must execute as a side-effect-free read-only audit of catalog headers, records, and checksums. |
| `THREATREC2` | **Deterministic Backup Management** | Atomic generation of `.bak` snapshot files with verified content before any destructive repair operations. |
| `THREATREC3` | **Quarantine Preservation & Crash-Consistent Repair** | Corrupted catalog files must be quarantined with timestamped extensions (`.corrupt.{timestamp}`) rather than overwritten or discarded. |
| `THREATREC4` | **Path Traversal & Device Sanitization (CWE-22)** | All file paths audited against directory climbing (`..`), UNC paths, control characters, and reserved system devices. |
| `THREATREC5` | **Safe Canonical Baseline Fallback** | If both the primary catalog and backup snapshot are unrecoverable, the subsystem can reseed the canonical STRIDE baseline. |

## 3. Defense-in-Depth & Error Classification

1. **CWE-22 (Path Traversal)**:
   - Rejected via `ThreatRecoveryService::validate_path` (`THREATREC_ERR_PATH_TRAVERSAL`).
2. **CWE-59 (Improper Link Resolution / Symlinks)**:
   - `symlink_metadata` checks verify that target files and backups are regular files.
3. **CWE-362 (Race Conditions / TOCTOU)**:
   - Atomic replacement via temporary files (`.tmp.{pid}.{nanos}`) ensuring write operations cannot leave half-written state during an ungraceful shutdown.
4. **CWE-400 (Resource Exhaustion)**:
   - File reads capped at 1 MiB (`MAX_THREAT_MODEL_STORE_SIZE`).

## 4. MCP Surface Architecture
Surfaced through tool `aios.threat.recovery`:
- `action: "verify"`: Execute deep structural verification and emit `ThreatIntegrityReport`.
- `action: "backup"`: Create snapshot backup `.bak`.
- `action: "repair"`: Repair recoverable records, salvage valid threat entries, and quarantine corrupted sources.
- `action: "restore"`: Overwrite live catalog from latest valid `.bak` snapshot.

## 5. Next Steps
- `T-02792`: Author formal specification `SPEC-THREAT-MODEL-RECOVERY.md`.
- `T-02793`: Scaffold `threat_model_recovery.rs` in `aiosh-core`.
