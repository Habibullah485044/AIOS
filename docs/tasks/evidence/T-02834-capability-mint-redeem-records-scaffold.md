# T-02834: Capability Mint/Redeem Records — Scaffold

- **Task**: `T-02834`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / capability mint/redeem records
- **Date**: 2026-10-04
- **Status**: PASSED

## 1. Summary of Changes
- Extended `PepGrant` and `CreateOpts` in `code/aiosh-cli/src/types.ts` and `code/aiosh-cli/src/pep.ts`:
  - Added `single_use?: boolean;`
  - Added `redeemed_at?: string;`
  - Added `RedeemResult` interface export.
- Scaffolded `PepGrantManager.redeem()` method signature in `code/aiosh-cli/src/pep.ts` that fails loudly (`NotImplementedError`) until implementation in `T-02835`.
- Verified compilation with `npm run build` (`tsc -p tsconfig.json`) - 0 errors.
- Verified zero regression on existing smoke suites (`tests/test_capability_cli_smoke.py` PASS).
