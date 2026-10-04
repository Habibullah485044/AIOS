# Evidence Artifact: T-02836 — capability mint/redeem records: Unit Test

## Task Information
- **Task ID**: `T-02836`
- **Subsystem**: `Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / capability mint/redeem records`
- **Title**: `capability mint/redeem records: Unit Test`
- **Status**: Completed

## Test Coverage
The unit test suite `code/aiosh-cli/tests/test_restraint_mint_redeem.py` was expanded to provide thorough unit coverage of Invariant `I-1` ("every grant issue writes a `pep.capability.mint` audit row and every use writes exactly one `pep.capability.redeem` row referencing the same token"):

1. **Mint Event Structure & Audit Verification**:
   - Mints a single-use capability grant.
   - Verifies `pep.capability.mint` row is emitted with `grant_token`, `tool`, `command`, `args`, and `c_flags`.
   - Verifies SQLite schema contains `single_use = 1` and `redeemed_at IS NULL`.

2. **Grant Status Pre-Redemption**:
   - Verifies capability state is unspent and active prior to invocation.

3. **Atomic Single-Use Redemption**:
   - Executes atomic SQL update on `pep_grants` where `redeemed_at IS NULL`.
   - Confirms rowcount updated == 1.
   - Emits `pep.capability.redeem` audit row with `outcome="ok"`.
   - Validates that `row2.prev_hash == row1.hash`.

4. **Double-Spend & Replay Protection**:
   - Executes second redemption attempt on the same token.
   - Confirms atomic SQL update yields rowcount == 0.
   - Proves single-use tokens cannot be double-spent.

5. **Hash Chain Completeness**:
   - Calls `audit_client.verify()` across the chain.
   - Validates 100% hash agreement across all entries.

6. **Expired Grant Rejection**:
   - Attempts redemption on grant where `expires_at < now`.
   - Proves expired grant redemption is strictly refused.

7. **Cryptographic Tamper Detection**:
   - Introduces out-of-band modification to audit record command without recomputing hash.
   - Verifies `audit_client.verify()` detects corruption immediately at `broken_at = 2`.

## Security Audit
- **Replay / Double-Spend Prevention**: Single-use status is enforced at the database level with atomic conditional write (`WHERE redeemed_at IS NULL`). No race condition can allow concurrent redemptions.
- **Fail-Closed on Expiry**: Grants whose TTL has elapsed fail the redemption check and cannot emit valid redeem records.
- **Hash Integrity Guarantee**: Any mutation of fields covered by canonical JSON hashing triggers immediate chain verification failure.

## Test Output
```
[1] Minting capability grant with pep.capability.mint audit record...
[+] Mint audit row written: hash=d97cbce88bfe5feb... seq=1
[2] Checking capability unspent status before redemption...
[+] Grant is unspent and active
[3] Redeeming capability grant with pep.capability.redeem audit record...
[+] Redeem audit row written: hash=d224167fe3a1f365... seq=2
[4] Attempting second redemption on single-use grant...
[+] Second redemption refused: single-use grant cannot be double-spent
[5] Verifying complete audit ring hash chain...
[+] Audit ring chain intact: checked 2 rows with 100% hash agreement
[6] Testing expired grant redemption rejection...
[+] Expired grant correctly rejected for redemption
[7] Testing cryptographic tamper detection in audit chain...
[+] Tamper detection verified: broken_at=2

[+] ALL RESTRIANT UNIT TESTS PASSED (T-02836 certified)
```
