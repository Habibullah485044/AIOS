# Security Review: T-02838 — capability mint/redeem records

## Task Information
- **Task ID**: `T-02838`
- **Subsystem**: `Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / capability mint/redeem records`
- **Title**: `capability mint/redeem records: Security Review`
- **Status**: Completed

## Security Audit & Invariant Verification

### 1. Invariant Verification
- **Invariant I-1 (1:1 Mint to Redeem Mapping for Single-Use Capabilities)**:
  - Verified: Every grant issuance emits a `pep.capability.mint` row in `audit_ring`.
  - Verified: Single-use grants enforce strict atomic redemption. Once redeemed, any subsequent attempt fails at both the SQL predicate level (`WHERE redeemed_at IS NULL`) and the in-memory check (`g.single_use && g.redeemed_at`).
  - Verified: Exactly one `pep.capability.redeem` row is emitted per single-use grant.

- **Standing Rule [PoR] Verification (Invariant I-2 Check)**:
  - Assessed state-changing paths added or modified:
    1. `PepGrantManager.create()`: Administrative grant minting. Protected by user privilege, emits audit record.
    2. `PepGrantManager.redeem()`: Pre-execution token consumption. Verifies expiry, token existence, scope matching, and single-use constraints. Fails closed on any error.
  - Confirmed: Downstream state-changing tool executions cannot proceed without a valid unredeemed token once the PEP gate is active.

### 2. Threat Modeling & Vulnerability Assessment
1. **Replay & Concurrency Attacks (Race Conditions / Double-Spend)**:
   - Threat: An agent or concurrent threads attempt to redeem the same single-use token simultaneously to execute two unauthorized actions.
   - Mitigation: SQLite executes in WAL mode with write serialization. The atomic conditional query:
     ```sql
     UPDATE pep_grants SET redeemed_at = ? WHERE grant_id = ? AND redeemed_at IS NULL
     ```
     ensures that exactly one concurrent transaction succeeds (`res.changes === 1`), while all competing transactions receive `res.changes === 0` and are immediately aborted.

2. **SQL Injection**:
   - Threat: Malicious input in `grant_id`, `actor`, `tool`, or `command` parameters corrupts the database.
   - Mitigation: All queries use strict parameterized bindings (`@grant_id`, `?`). Zero string concatenation.

3. **Time-of-Check to Time-of-Use (TOCTOU)**:
   - Threat: An adversary checks grant validity, revokes or redeems it elsewhere, and proceeds to execute.
   - Mitigation: Redemption is coupled to the atomic database update before execution begins.

4. **Cryptographic Integrity & Anti-Repudiation**:
   - Threat: Operator modifies or deletes mint/redeem records to conceal capability abuse.
   - Mitigation: Audit records are inserted into `audit_ring` where each record is hashed:
     ```
     hash = sha256Hex(prev_hash + canonicalJson(proto))
     ```
     Any tampering, deletion, or re-ordering breaks chain verification across both TypeScript and Python verifiers.

### 3. Hardening Recommendations (To Be Addressed in T-02839)
- Explicit differentiation between single-use conditional update and multi-use update in `redeem()`.
- Add explicit bounds check on `command` and `tool` length to prevent denial-of-service via huge payloads.
- Ensure all datetime strings adhere strictly to ISO 8601 UTC.
