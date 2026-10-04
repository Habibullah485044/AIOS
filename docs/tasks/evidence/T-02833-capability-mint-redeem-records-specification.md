# T-02833: Capability Mint/Redeem Records — Specification Summary

- **Task**: `T-02833`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / capability mint/redeem records
- **Date**: 2026-10-04
- **Status**: PASSED

## Summary
Specified the contract for capability mint and redeem records conforming to Invariant I-1:
- Type extensions for `PepGrant`, `CreateOpts`, and `RedeemResult`.
- Database schema migration adding `single_use` and `redeemed_at` to `pep_grants`.
- Explicit contracts for `PepGrantManager.create()` (emitting `pep.capability.mint`) and `PepGrantManager.redeem()` (emitting `pep.capability.redeem`).
- Failure envelopes and refusal audit records.
- Detailed spec captured in `docs/tasks/evidence/T-02833-spec.md`.
