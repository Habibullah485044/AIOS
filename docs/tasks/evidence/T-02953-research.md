# Research Document: Compliance Mapping Recovery & Validation (T-02953)

- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Compliance Mapping Recovery & Validation
- **Focus**: Integrity Verification, Automated Snapshots, Crash Repair, and Quarantine Mechanics
- **Bindings**: ADR-0035 §I-1, ADR-0037 §D-1

## 1. Executive Summary

The Compliance Mapping Recovery & Validation subsystem provides disaster recovery, structural verification, corruption quarantine, and snapshot restoration for the regulatory compliance persistence file (`docs/compliance_map.json`). In the event of process crashes, power failures, storage degradation, or malicious tampering, this subsystem enables automated discovery of invalid records, isolates damaged inputs into quarantine storage, restores known-good `.bak` snapshots, or falls back safely to canonical NIST/ISO baselines without compromising security invariants.

## 2. Invariants & Recovery Requirements

| Invariant | Name | Description |
|:---|:---|:---|
| `COMPLYREC1` | **Non-Destructive Integrity Verification** | `verify_integrity` must execute as a side-effect-free read-only audit of catalog schema, mappings, and bounds. |
| `COMPLYREC2` | **Deterministic Backup Management** | Atomic generation of `.bak` snapshot files with verified content before any destructive repair operations. |
| `COMPLYREC3` | **Quarantine Preservation & Crash-Consistent Repair** | Corrupted catalog files must be quarantined with timestamped extensions (`.corrupt.{timestamp}`) rather than overwritten or discarded. |
| `COMPLYREC4` | **Path Traversal & Device Sanitization (CWE-22)** | All file paths audited against directory climbing (`..`), UNC paths, control characters, and reserved system devices. |
| `COMPLYREC5` | **Safe Canonical Baseline Fallback** | If both the primary catalog and backup snapshot are unrecoverable, the subsystem can reseed the canonical compliance baseline. |

## 3. Defense-in-Depth & Error Classification

1. **CWE-22 (Path Traversal)**:
   - Rejected via `ComplianceRecoveryService::validate_path` (`COMPLYREC_ERR_PATH_TRAVERSAL`).
2. **CWE-59 (Improper Link Resolution / Symlinks)**:
   - `symlink_metadata` checks verify that target files and backups are regular files.
3. **CWE-362 (Race Conditions / TOCTOU)**:
   - Atomic replacement via temporary files (`.tmp.{pid}.{nanos}`) ensuring write operations cannot leave half-written state during an ungraceful shutdown.
4. **CWE-400 (Resource Exhaustion)**:
   - File reads capped at 1 MiB (`MAX_COMPLIANCE_STORE_SIZE`).
   - Catalog mappings capped at 1,024 entries (`MAX_COMPLIANCE_ENTRIES_CAPACITY`).

## 4. MCP Surface Architecture

Surfaced through tool `aios.compliance` via recovery actions:
- `action: "recovery-verify"`: Execute deep structural verification and emit `ComplianceIntegrityReport`.
- `action: "recovery-backup"`: Create snapshot backup `.bak`.
- `action: "recovery-repair"`: Repair recoverable records, salvage valid compliance mappings, and quarantine corrupted sources.
- `action: "recovery-restore"`: Overwrite live catalog from latest valid `.bak` snapshot.

## 5. Next Steps
- `T-02954`: Author formal specification `SPEC-COMPLIANCE-RECOVERY.md`.
- `T-02955`: Scaffold `compliance_recovery.rs` in `aiosh-core` and Python parity.
