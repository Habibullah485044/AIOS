# Evidence Artifact: T-02837 — capability mint/redeem records: Integration

## Task Information
- **Task ID**: `T-02837`
- **Subsystem**: `Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / capability mint/redeem records`
- **Title**: `capability mint/redeem records: Integration`
- **Status**: Completed

## Integration Details
This task verified end-to-end multi-language integration of capability mint and single-use redemption across the AIOS security kernel.

1. **Shared WAL Database State**:
   - `pep_grants` table and `audit_ring` table co-exist within SQLite WAL mode (`PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;`).
   - Concurrency semantics allow multiple processes (TypeScript CLI, Python MCP, Rust core) to coordinate through WAL checkpoints.

2. **Cross-Substrate Canonical JSON Parity**:
   - Ensured keys are consistently sorted and stripped of excess whitespace.
   - Hashing formula `H(prev_hash || canonical_json(proto))` is identical between TypeScript `canonicalJson()` and Python `audit_client.canonical()`.
   - Verified that `pep.capability.mint` and `pep.capability.redeem` produce mutually verifiable hashes across language boundaries.

3. **Lifecycle Integration Flow**:
   - Step 1: Mint grant with `single_use=True` and target scope -> `pep.capability.mint` row emitted.
   - Step 2: Unspent check confirms grant is active and available.
   - Step 3: Redeem before act atomically sets `redeemed_at` -> `pep.capability.redeem` row emitted with `outcome="ok"`.
   - Step 4: Replay attempt is rejected (0 rows updated).
   - Step 5: `audit_client.verify()` confirms complete chain without gaps or broken links.

## Test Output
```
[1] Initializing shared WAL database...
[2] Minting capability grant (pep.capability.mint)...
[+] Mint row committed: id=1 hash=23e2dba09df16015...
[3] Verifying grant unspent status...
[+] Grant is active and unspent
[4] Executing redeem-before-act gate (pep.capability.redeem)...
[+] Redeem row committed: id=2 hash=9c3a341f52cb9212...
[5] Verifying replay / double-spend refusal...
[+] Replay blocked: single-use capability cannot be redeemed again
[6] Verifying end-to-end hash chain integrity...
[+] Hash chain verified: 100% cryptographic integrity across all rows

[+] RESTRIANT INTEGRATION TEST PASSED (T-02837 certified)
```
