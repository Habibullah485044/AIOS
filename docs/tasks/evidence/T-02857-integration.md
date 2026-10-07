# Integration: Chain Anchoring & Completeness Checkpoints (T-02857)

**Task**: `T-02857` — Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / chain anchoring & completeness checkpoints: Integration  
**Date**: 2026-10-07  
**Author**: Antigravity System  
**Status**: Integrated  

---

## 1. Production Surfaces Wired

1. **FastMCP Server Surface (`code/aiosh-mcp/aiosh_mcp/server.py`)**:
   - Registered `aios_anchor_create`: Creates an Ed25519-signed anchor for the current chain head and appends to `$AIOSH_HOME/anchors/anchors.jsonl`. Emits an audit row for `aios.anchor.create`.
   - Registered `aios_anchor_verify`: Validates live audit chain rows against external signed anchors. Checks for key mismatches, signatures, truncations, and forks.
   - Added helper `head()` to `code/aiosh-mcp/aiosh_mcp/audit_client.py` for reading the current head AuditRow.

2. **CLI Surface (`code/aiosh-cli/src/cli.ts`)**:
   - Added command group `aiosh anchor`:
     - `aiosh anchor create [--key <hex>]`: Signs current audit ring head and appends to `$AIOSH_HOME/anchors/anchors.jsonl`.
     - `aiosh anchor verify [--pubkey <hex>]`: Validates audit chain consistency against external anchors.

3. **End-to-End Test Suite (`code/aiosh-mcp/tests/test_por_anchoring_integration.py`)**:
   - Verified that anchor creation writes to `anchors.jsonl` and records an audit row in `audit_ring`.
   - Verified that `aios_anchor_verify` confirms valid chain state.
   - Verified that forking/tampering triggers `FORK_DETECTED`.
   - Verified that truncation triggers `TRUNCATION_DETECTED`.
   - Ran `pytest` suite: all 11 integration and unit tests passing.
