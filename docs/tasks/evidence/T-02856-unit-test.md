# Unit Test: Chain Anchoring & Completeness Checkpoints (T-02856)

**Task**: `T-02856` — Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / chain anchoring & completeness checkpoints: Unit Test  
**Date**: 2026-10-07  
**Author**: Antigravity System  
**Status**: Passed (9/9 unit tests)  

---

## 1. Test Suite Coverage

Created comprehensive automated test suite `code/aiosh-mcp/tests/test_por_chain_anchoring.py` verifying:
1. `test_keypair_generation`: Validates Ed25519 64-hex private and public key generation.
2. `test_sign_and_verify_checkpoint`: Validates signing of (seq, head_hash, timestamp) and verification against embedded pubkey.
3. `test_tampered_anchor_detection`: Validates that altering `seq`, `head_hash`, `timestamp`, or corrupting `signature` immediately fails verification.
4. `test_chain_verification_against_anchors_happy_path`: Validates complete 100-row chain against multiple signed anchors.
5. `test_chain_truncation_detection`: Validates that dropping trailing rows (e.g., chain truncated to 80 rows when anchor was signed at 100) fails with `TRUNCATION_DETECTED`.
6. `test_chain_fork_and_rewrite_detection`: Validates that modifying an intermediate row's hash fails with `FORK_DETECTED`.
7. `test_untrusted_pubkey_rejection`: Validates that anchor signed with key $K_1$ is rejected when verified against trusted pubkey $K_2$.
8. `test_anchor_persistence_roundtrip`: Validates JSONL file appending and deserialization roundtrip.
9. `test_key_separation_invariant`: Validates that `audit.db` schema does not contain private key columns, preserving Invariant I-3.

## 2. Test Execution Results
- `python code/aiosh-mcp/tests/test_por_chain_anchoring.py` -> 9/9 passed.
- `python -m pytest code/aiosh-mcp/tests/test_por_chain_anchoring.py` -> 9 passed in 0.34s.
