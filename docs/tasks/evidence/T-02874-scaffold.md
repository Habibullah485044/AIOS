# Task Evidence: T-02874 — Standalone Proof Verifier: Scaffold

- **Task ID**: `T-02874`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / standalone proof verifier
- **Date**: 2026-10-07
- **Invariants Scaffolding**: `I-4` (Self-Contained Verifier Model)

## Scaffold Deliverables
1. **Python Module**:
   - Created `code/aiosh-mcp/aiosh_mcp/verifier.py`.
   - Declared frozen dataclass `VerificationResult(valid: bool, proof_id: str, reason: Optional[str], checks: dict)`.
   - Declared function stub `verify_restraint_proof(...)` raising `NotImplementedError`.
   - Verified import cleanly in Python.

2. **TypeScript Module**:
   - Created `code/aiosh-cli/src/verifier.ts`.
   - Declared `VerificationResult` interface.
   - Declared function stub `verifyRestraintProof(...)` throwing `Error("T-02874 SCAFFOLD")`.
   - Rebuilt TypeScript with zero compile or typing errors (`npm run build`).

## Test & Build Telemetry
```
python -c "from aiosh_mcp.verifier import VerificationResult, verify_restraint_proof; print('Python import OK')" -> OK
npm run build (tsc -p tsconfig.json) -> 0 errors, exit code 0
```
