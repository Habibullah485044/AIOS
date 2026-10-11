# Security Review: Compliance Mapping Recovery & Validation (T-02959)

- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / Recovery & Validation
- **Task ID**: `T-02959`
- **Reviewer**: Security Kernel Auditor / Antigravity
- **Date**: 2026-10-11
- **Status**: PASSED (No blocking vulnerabilities or policy bypasses)

---

## 1. Threat Modeling & Abuse Scenarios

### Scenario 1: Path Traversal & Symlink Arbitrary File Read / Overwrite (CWE-22 / CWE-59)
- **Threat**: An attacker supplies a path containing directory traversal sequences (`../../etc/passwd`) or UNC shares (`\\\\malicious-host\\share`), or points to a symlink pointing outside the sandbox, attempting to read sensitive host files or overwrite arbitrary files during backup/restore.
- **Defense & Verification**:
  - `ComplianceRecoveryService::validate_path` (Rust and Python):
    - Rejects empty strings, strings containing `..`, strings starting with `\\\\` or `//`.
    - Rejects any control characters (ASCII < 32).
    - Enforces maximum path component depth limit of 16.
    - Checks `symlink_metadata`: explicitly rejects symlinks (`is_symlink() == true`).
  - Unit tests in `test_compliance_recovery_unit.rs` and `test_compliance_recovery_unit.py` verify that `../`, `..\\`, UNC, and depth violations return `COMPLYREC_ERR_PATH_TRAVERSAL`.

### Scenario 2: Resource Exhaustion / Denial-of-Service via Oversized Catalogs (CWE-400)
- **Threat**: An attacker crafts a massive multi-gigabyte JSON catalog or endless deeply nested JSON to trigger Out-Of-Memory (OOM) or CPU starvation during integrity verification.
- **Defense & Verification**:
  - Both Rust and Python verify `stat().st_size <= MAX_COMPLIANCE_STORE_SIZE` (5 MB) before reading or parsing file bytes.
  - If size exceeds 5 MB, verification aborts immediately with `COMPLYREC_ERR_FILE_SIZE` and flags `OversizedPayload`.
  - Max entry capacity bounded by `MAX_COMPLIANCE_ENTRIES_CAPACITY` (1024).

### Scenario 3: State-Tampering & Quarantine Bypass (CWE-362)
- **Threat**: An attacker corrupts the catalog file, then triggers repair hoping to scrub audit trails or delete corrupted forensic evidence before incident responders inspect it.
- **Defense & Verification**:
  - `repair_catalog` and `restore_from_backup` **never** delete the existing corrupted file without first creating an unalterable quarantine snapshot (`.corrupt.<pid>.<nanos>`).
  - Quarantine copy creation is performed prior to any modifications to the target file.
  - Atomic write patterns guarantee that a power cut or crash mid-repair does not leave a zero-byte or half-written catalog.

### Scenario 4: Unauthorized Mutation via MCP Surface (PoR Invariant I-2)
- **Threat**: An untrusted caller invokes `recovery-backup`, `recovery-repair`, or `recovery-restore` without presenting a valid cryptographic Capability Token.
- **Defense & Verification**:
  - In `code/aiosh-mcp/aiosh_mcp/compliance.py`:
    - `recovery-verify` is listed in `READ_ACTIONS` (read-only inspection).
    - `recovery-backup`, `recovery-repair`, and `recovery-restore` are listed in `WRITE_ACTIONS`.
    - Mutating actions strictly require and redeem a valid capability token (`grant_id`), validated by PEP before execution.
  - In `code/aiosh-rust/aiosh-cli/src/main.rs`:
    - Every subcommand (`verify`, `backup`, `repair`, `restore`) writes an append-only audit record into SQLite WAL (`classify_and_emit`).

---

## 2. Invariant Check Matrix

| Invariant | Description | Verification Status |
| :--- | :--- | :--- |
| **I-1** | Bounded Memory & Execution Time | **VERIFIED** — 5MB file cap, 1024 max entries. |
| **I-2** | PoR Capability Gating on Mutation | **VERIFIED** — All recovery mutators require valid grant. |
| **I-3** | Tamper-Evident Audit Emission | **VERIFIED** — Exactly 1 audit event emitted per CLI action. |
| **I-4** | Zero Unquarantined State Deletion | **VERIFIED** — Pre-repair quarantine snapshots mandatory. |
| **I-5** | Safe Path Sanitization | **VERIFIED** — Rejects `..`, symlinks, control chars, UNC. |

---

## 3. Conclusion & Sign-Off
All 5 abuse scenarios are securely mitigated with defenses verified in automated unit and integration suites. No policy bypasses or unhandled failure modes remain. Subsystem is approved for hardening.
