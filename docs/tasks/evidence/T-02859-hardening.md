# Hardening: Chain Anchoring & Completeness Checkpoints (T-02859)

**Task**: `T-02859` — Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / chain anchoring & completeness checkpoints: Hardening  
**Date**: 2026-10-07  
**Author**: Antigravity System  
**Status**: Hardened & Verified  

---

## 1. Hardening Measures Implemented

1. **Strict Hex Key Validation (`_validate_hex_key` / `validateHexKey`)**:
   - Private and public keys must strictly match 64 hex characters (32 bytes) via regex and byte decoding.
   - Malformed or truncated keys fail fast with descriptive `ValueError` / `Error`, preventing unhandled crashes or edge-case key interpretations.

2. **File Size Capping (`MAX_ANCHORS_FILE_SIZE = 10MB`)**:
   - `load_anchors()` checks file size before opening to prevent memory exhaustion / DoS from oversized or malicious anchor logs.

3. **Restricted Storage Permissions**:
   - `append_anchor()` enforces directory permissions (`0700`) and file permissions (`0600`) on non-Windows platforms, ensuring only the owner process can read or append anchor logs.

4. **Fail-Closed Line Parsing**:
   - Corrupted, truncated, or syntactically invalid lines in `anchors.jsonl` trigger an explicit error with the exact line number (`Corrupted anchor record at line X`), preventing partial or silent omission of security checkpoints.

5. **Signature Length Assertion**:
   - Verification checks that signatures are strictly 128 hex characters (64 bytes) before cryptographic validation.
