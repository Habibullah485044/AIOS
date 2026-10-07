# Evidence Artifact: T-02840 — capability mint/redeem records: Documentation

## Task Information
- **Task ID**: `T-02840`
- **Subsystem**: `Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / capability mint/redeem records`
- **Title**: `capability mint/redeem records: Documentation`
- **Status**: Completed

## Summary of Documentation Work
1. Created comprehensive specification document:
   - `docs/SPEC-RESTRAINT-MINT-REDEEM.md`
2. Detailed architectural integration of Layer 1 Proof of Restraint:
   - Invariant I-1 (1:1 Mint to Redeem parity).
   - Invariant I-2 (Atomic single-use enforcement).
   - SQLite schema specifications for `pep_grants` table (`single_use`, `redeemed_at`).
   - Audit event structures for `pep.capability.mint` and `pep.capability.redeem`.
3. Provided copy-pasteable programmatic examples for TypeScript (`PepGrantManager`, `AuditRing`) and cross-substrate verification in Python (`aiosh_mcp.audit_client`).
4. Stated constraints and known limitations honestly:
   - Requirement of Layer 2 external checkpoints to resist operator chain rewrite attacks.
   - Fail-closed crash semantics on abnormal process termination.
5. Linked all preceding task evidence files (T-02832 through T-02839).
