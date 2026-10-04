# T-02835: Capability Mint/Redeem Records — Implementation

- **Task**: `T-02835`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / capability mint/redeem records
- **Date**: 2026-10-04
- **Status**: PASSED

## 1. Summary of Changes
- Extended `PepStore` in `code/aiosh-cli/src/pep.ts`:
  - `init_()`: Adds `single_use` and `redeemed_at` columns to `pep_grants` table using idempotent migration helper `maybeAddColumn_`.
  - `create(opts: CreateOpts, ring?: AuditRing)`: Sets `single_use` on grant record. When `ring` is provided, automatically writes a `pep.capability.mint` audit row with `grant_token = grant_id`, matching `canonicalJson` invariants.
  - `get()` and `list()`: Populates `single_use` (boolean) and `redeemed_at` (ISO timestamp).
  - `check()`: Rejects authorization if `g.single_use && g.redeemed_at` with `"grant <id> already redeemed at <ts>"`.
  - `redeem()`: Implemented atomic pre-execution redemption:
    - Atomically updates `pep_grants SET redeemed_at = ? WHERE grant_id = ? AND redeemed_at IS NULL`.
    - Detects concurrent double-spend attempts.
    - Writes `pep.capability.redeem` audit row with `grant_token = grant_id` into the WAL audit chain.
- Added comprehensive unit test `code/aiosh-cli/tests/test_restraint_mint_redeem.py` exercising the full lifecycle:
  - Minting with `pep.capability.mint` row.
  - Pre-redemption validity checks.
  - Redemption with `pep.capability.redeem` row.
  - Double redemption refusal.
  - Cryptographic verification of the complete hash chain (`audit_client.verify()`).

## 2. Invariants Certified
- `I-1`: Every grant issue writes a `pep.capability.mint` audit row; every grant use writes exactly one `pep.capability.redeem` row referencing the same token.
- Cross-substrate canonical JSON parity preserved.
