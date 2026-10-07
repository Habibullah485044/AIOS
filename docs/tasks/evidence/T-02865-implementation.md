# Implementation: Restraint Proof Generator (T-02865)

**Task**: `T-02865` — Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / restraint proof generator: Implementation  
**Date**: 2026-10-07  
**Author**: Antigravity System  
**Status**: Implemented  

---

## 1. Summary of Changes

1. **Python Implementation (`code/aiosh-mcp/aiosh_mcp/restraint.py`)**:
   - Implemented `generate_restraint_proof()` validating grant existence, unredeemed status (`redeemed_at IS NULL` and absence of `pep.capability.redeem` rows).
   - Wired bounding anchor selection (`start_anchor` and `end_anchor`) covering $[T_{start}, T_{end}]$ from `$AIOSH_HOME/anchors/anchors.jsonl`.
   - Wired archived segment checking via bit-identical Bloom filter testing (`bloom_test`), verifying zero false negatives for non-use.
   - Wired live range hash traversal collecting contiguous chain hashes.
   - Emits structured `RestraintProofPackage` with `verdict: "PROVABLY_RESTRAINED"`.

2. **TypeScript Implementation (`code/aiosh-cli/src/restraint.ts`)**:
   - Implemented cross-substrate mirror of `generateRestraintProof()`.
   - Verified compilation (`npm run build`) with zero type errors.

3. **PEP Schema Alignment**:
   - Hardened `ensure_pep_schema()` in `audit_client.py` to ensure `single_use` and `redeemed_at` columns exist and migrate seamlessly.

4. **Testing**:
   - Verified targeted restraint generation asserting `PROVABLY_RESTRAINED` verdict and grant binding.
   - Confirmed 11/11 tests passing in pytest with zero regressions.
