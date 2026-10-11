# Specification: Compliance Mapping Store Recovery & Integrity Validation (SPEC-COMPLIANCE-RECOVERY)

- **Status**: IMPLEMENTED & VERIFIED
- **Date**: 2026-10-11
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Compliance Mapping Recovery & Validation
- **Binding**: ADR-0035 §I-1, ADR-0037 §D-1, PoR Invariant I-2
- **Source Code**:
  - Rust Core: [`code/aiosh-rust/aiosh-core/src/compliance_recovery.rs`](../code/aiosh-rust/aiosh-core/src/compliance_recovery.rs)
  - Rust CLI: [`code/aiosh-rust/aiosh-cli/src/main.rs`](../code/aiosh-rust/aiosh-cli/src/main.rs)
  - Python Recovery: [`code/aiosh-mcp/aiosh_mcp/compliance_recovery.py`](../code/aiosh-mcp/aiosh_mcp/compliance_recovery.py)
  - Python MCP Tool: [`code/aiosh-mcp/aiosh_mcp/compliance.py`](../code/aiosh-mcp/aiosh_mcp/compliance.py)

---

## 1. Overview

The Compliance Mapping Recovery subsystem safeguards the regulatory compliance catalog (`docs/compliance_map.json`) against crashes, partial writes, corrupted serialization, and filesystem tampering. It provides non-destructive inspection, atomic repairs, timestamped quarantine preserving damaged data, automated quarantine rotation, and snapshot restoration.

---

## 2. Data Types & Shipped Interfaces

```rust
pub const COMPLYREC_ERR_IO: &str = "COMPLYREC_ERR_IO";
pub const COMPLYREC_ERR_PARSE: &str = "COMPLYREC_ERR_PARSE";
pub const COMPLYREC_ERR_PATH_TRAVERSAL: &str = "COMPLYREC_ERR_PATH_TRAVERSAL";
pub const COMPLYREC_ERR_FILE_SIZE: &str = "COMPLYREC_ERR_FILE_SIZE";
pub const COMPLYREC_ERR_VALIDATION: &str = "COMPLYREC_ERR_VALIDATION";
pub const COMPLYREC_ERR_NO_BACKUP: &str = "COMPLYREC_ERR_NO_BACKUP";
pub const MAX_QUARANTINE_FILES: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceCatalogStatus {
    Healthy,
    Degraded,
    Corrupted,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceIssueSeverity {
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceIssueType {
    MissingCatalogFile,
    InvalidJsonSyntax,
    SchemaMismatch,
    CorruptedEntry,
    DuplicateMappingId,
    OversizedPayload,
    SymlinkForbidden,
    InvalidPathTraversal,
    InvalidTimestamp,
}

pub struct ComplianceRecoveryService;

impl ComplianceRecoveryService {
    pub fn validate_path(path: &Path) -> Result<PathBuf, String>;
    pub fn backup_path_for(path: &Path) -> PathBuf;
    pub fn quarantine_path_for(path: &Path) -> PathBuf;
    pub fn prune_old_quarantine_files(parent: &Path, base_fname: &str) -> usize;
    pub fn create_backup(path: &Path) -> Result<PathBuf, String>;
    pub fn verify_integrity(path: &Path) -> ComplianceIntegrityReport;
    pub fn repair_catalog(path: &Path) -> Result<ComplianceRecoveryReport, String>;
    pub fn restore_from_backup(path: &Path) -> Result<ComplianceRecoveryReport, String>;
}
```

---

## 3. Invariants & Security Guarantees

- **`COMPLYREC1` (Non-Destructive Verification)**: `verify_integrity` performs read-only checks without mutating file contents or altering existing backups.
- **`COMPLYREC2` (Deterministic Atomic Backup)**: `create_backup` produces `<path>.bak` snapshots via PID-stamped temporary files, ensuring atomic replacement and zero partial backups.
- **`COMPLYREC3` (Quarantine Preservation & Rotation)**: Corrupted catalogs are quarantined with unique timestamped filenames (`<path>.corrupt.<pid>.<nanos>`) before salvage or repair. Quarantine files are pruned to keep at most `MAX_QUARANTINE_FILES` (10) to prevent disk exhaustion (CWE-400).
- **`COMPLYREC4` (Path Traversal & Symlink Rejection)**: Path traversals (`..`), UNC paths (`\\\\`, `//`), control characters, path depth > 16, and symlinks are strictly rejected (`COMPLYREC_ERR_PATH_TRAVERSAL`).
- **`COMPLYREC5` (Safe Baseline Fallback)**: Completely unparseable JSON files safely preserve the original file in quarantine and reseed from canonical compliance baselines.
- **`PoR Invariant I-2` (PEP Capability Gating)**:
  - Read actions (`verify`, `recovery-verify`) require no capability grant.
  - State-changing actions (`backup`, `repair`, `restore`, `recovery-backup`, `recovery-repair`, `recovery-restore`) strictly require a redeemed Capability Token under PEP gating.

---

## 4. Operator Invocation Guide (CLI & MCP)

### 4.1 Rust CLI Commands (`aiosh compliance`)

Inspect catalog integrity:
```bash
aiosh compliance verify --path docs/compliance_map.json
aiosh compliance verify --path docs/compliance_map.json --json
```

Create snapshot backup:
```bash
aiosh compliance backup --path docs/compliance_map.json
```

Repair damaged catalog (quarantines original, salvages valid entries):
```bash
aiosh compliance repair --path docs/compliance_map.json
```

Restore catalog from `.bak` backup:
```bash
aiosh compliance restore --path docs/compliance_map.json
```

### 4.2 MCP Tool Actions (`compliance`)

Call via JSON-RPC / MCP client:
```json
{
  "name": "compliance",
  "arguments": {
    "action": "recovery-verify"
  }
}
```

Mutating recovery with capability grant:
```json
{
  "name": "compliance",
  "arguments": {
    "action": "recovery-repair",
    "grant_id": "grant-compliance-operator-token"
  }
}
```

---

## 5. Constraints & Known Limitations

1. **Storage Format**: Only canonical UTF-8 JSON compliance stores are supported (SQLite WAL audit records remain separate in `audit.db`).
2. **Payload Size Bound**: Store files exceeding `MAX_COMPLIANCE_STORE_SIZE` (5 MB) are rejected to prevent memory exhaustion.
3. **Quarantine Limit**: The system retains the 10 most recent `.corrupt.*` quarantine snapshots per catalog directory; older files are automatically pruned.
4. **Single Host Storage**: File recovery assumes local POSIX or Windows NTFS filesystems; network shares (SMB/UNC) are deliberately prohibited for security.

---

## 6. Task Evidence Traceability

- Research: [`docs/tasks/evidence/T-02953-recovery-validation-research.md`](tasks/evidence/T-02953-recovery-validation-research.md)
- Specification: [`docs/tasks/evidence/T-02954-recovery-validation-specification.md`](tasks/evidence/T-02954-recovery-validation-specification.md)
- Scaffold: [`docs/tasks/evidence/T-02955-recovery-validation-scaffold.md`](tasks/evidence/T-02955-recovery-validation-scaffold.md)
- Implementation: [`docs/tasks/evidence/T-02956-recovery-validation-implementation.md`](tasks/evidence/T-02956-recovery-validation-implementation.md)
- Unit Testing: [`docs/tasks/evidence/T-02957-recovery-validation-unit-test.md`](tasks/evidence/T-02957-recovery-validation-unit-test.md)
- Integration: [`docs/tasks/evidence/T-02958-recovery-validation-integration.md`](tasks/evidence/T-02958-recovery-validation-integration.md)
- Security Review: [`docs/tasks/evidence/T-02959-recovery-validation-security-review.md`](tasks/evidence/T-02959-recovery-validation-security-review.md)
- Hardening: [`docs/tasks/evidence/T-02960-recovery-validation-hardening.md`](tasks/evidence/T-02960-recovery-validation-hardening.md)
