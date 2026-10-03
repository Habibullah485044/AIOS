# Specification: Secrets Handling Recovery & Validation (SPEC-SECRETS-RECOVERY)

- **Status**: IMPLEMENTED & HARDENED
- **Date**: 2026-10-03
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Secrets Handling Recovery & Validation
- **Binding**: ADR-0035 §G-1

## 1. Overview
The Secrets Handling Recovery and Validation subsystem provides deterministic integrity verification, crash-consistent persistence, backup creation, and safe repair mechanics for the AIOS secrets vault.

## 2. Invariants & Guarantees
1. **Zero-Disclosure Invariant**: Plaintext secret payloads, decryption keys, and private seeds are never logged in validation reports, repair actions, or error outputs.
2. **Quarantine Scrubbing**: Quarantined corrupt records stored in `<vault>.corrupt.<ts>.json` have any `payload_hex` values scrubbed with `"[SCRUBBED_ON_QUARANTINE]"` to prevent residual credential exposure on disk.
3. **Crash Consistency**: Mutations are written to a temporary staging file (`<path>.tmp`), flushed to disk, and replaced via atomic filesystem rename (`std::fs::rename`).
4. **Pre-Mutation Snapshot**: High-risk mutations or explicit backups snapshot current vault state to `<path>.bak`.
5. **Path Sanitization**: All vault, backup, and quarantine paths reject path traversal (`..`), UNC paths (`\\\\`, `//`), and control characters.
6. **Deterministic Repair**: Salvageable records are preserved; malformed or unparseable records are quarantined to prevent permanent data loss while restoring vault usability.

## 3. Data Structures

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretVaultStatus {
    Healthy,
    Degraded,
    Corrupted,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretIssueSeverity {
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretIntegrityIssue {
    pub severity: SecretIssueSeverity,
    pub issue_type: String,
    pub secret_id: Option<String>,
    pub details: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretIntegrityReport {
    pub vault_path: String,
    pub status: SecretVaultStatus,
    pub total_records: usize,
    pub valid_records: usize,
    pub corrupted_records: usize,
    pub issues: Vec<SecretIntegrityIssue>,
    pub has_backup: bool,
    pub backup_path: Option<String>,
    pub timestamp: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRecoveryAction {
    pub action_type: String,
    pub target_id: Option<String>,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRecoveryReport {
    pub vault_path: String,
    pub success: bool,
    pub actions: Vec<SecretRecoveryAction>,
    pub records_recovered: usize,
    pub records_dropped: usize,
    pub quarantined_path: Option<String>,
    pub timestamp: String,
}
```

## 4. API Specification
- `SecretRecoveryService::validate_vault(path: &Path) -> Result<SecretIntegrityReport, String>`
- `SecretRecoveryService::create_backup(path: &Path) -> Result<PathBuf, String>`
- `SecretRecoveryService::restore_from_backup(path: &Path) -> Result<SecretRecoveryReport, String>`
- `SecretRecoveryService::repair_vault(path: &Path, quarantine: bool) -> Result<SecretRecoveryReport, String>`

## 5. CLI Interface Reference
The operator CLI provides subcommands under `aiosh secret recovery`:
- `aiosh secret recovery check [--store <PATH>] [--json]`: Run read-only integrity inspection. Returns exit code 0 if Healthy, 1 if Corrupted or Missing, 2 on invalid arguments.
- `aiosh secret recovery backup [--store <PATH>] [--json]`: Create `<store>.bak` snapshot atomically.
- `aiosh secret recovery restore [--store <PATH>] [--json]`: Revert vault to `<store>.bak` after verifying backup integrity.
- `aiosh secret recovery repair [--store <PATH>] [--quarantine] [--json]`: Repair vault, dropping or quarantining corrupt records and regenerating a valid vault.

## 6. Evidence Links
- Research: `docs/tasks/evidence/T-02691-recovery-validation-research.md`
- Specification: `docs/tasks/evidence/T-02692-recovery-validation-specification.md`
- Scaffold: `docs/tasks/evidence/T-02693-recovery-validation-scaffold.md`
- Implementation: `docs/tasks/evidence/T-02694-recovery-validation-implementation.md`
- Unit Test: `docs/tasks/evidence/T-02695-recovery-validation-unit-test.md`
- Integration: `docs/tasks/evidence/T-02696-recovery-validation-integration.md`
- Security Review: `docs/tasks/evidence/T-02697-recovery-validation-security-review.md`
- Hardening: `docs/tasks/evidence/T-02698-recovery-validation-hardening.md`
