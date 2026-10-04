# T-02832: Capability Mint/Redeem Records — Research Summary

- **Task**: `T-02832`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / capability mint/redeem records
- **Date**: 2026-10-04
- **Status**: PASSED

## Summary
Completed research establishing facts, constraints, and prior art for the capability mint/redeem records of Proof of Restraint.
- Audited `code/aiosh-cli/src/pep.ts` and `code/aiosh-cli/src/audit.ts`.
- Identified that existing grants lack `single_use` and `redeemed_at` tracking.
- Formalized requirement for atomic `pep.capability.mint` and `pep.capability.redeem` audit row emissions.
- Detailed evidence captured in `docs/tasks/evidence/T-02832-research.md`.
