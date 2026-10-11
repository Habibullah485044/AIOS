# Artifact: T-02930 Compliance Mapping Security Policy Hardening

- **Task**: T-02930 (Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / security policy: Hardening)
- **Status**: Complete
- **Hardening Enhancements Applied**:
  1. **Bounded Pre-Read & Stream Caps**:
     - In Rust (`compliance_policy.rs`): replaced unbounded `read_to_string` with bounded `Read::take(MAX_COMPLIANCE_SECURITY_POLICY_BYTES + 1)` buffer reads. Pre-check and post-read size checks prevent TOCTOU race condition memory exhaustion.
     - In Python (`compliance_policy.py`): applied bounded `read(MAX_COMPLIANCE_SECURITY_POLICY_BYTES + 1)` and size checks.
  2. **Temporary File & Resource Leak Prevention**:
     - In atomic file saves (`save_to_path` in Rust and `save_to_file` in Python), temporary files use unique process-specific naming (`.tmp.<pid>`).
     - Added guaranteed cleanup (`finally: if tmp.exists(): tmp.unlink()`) on all failure paths ensuring zero temporary residue accumulation.
  3. **Strict Validation Invariants**:
     - Added length bounds on policy version strings (`<= 32` bytes) and permitted framework counts (`<= 16`).
     - Added explicit NaN and boundary checks for float compliance percentage thresholds.
  4. **Fail-Closed Envelopes**:
     - All failure paths return typed error codes (`COMPLIANCEPOL_ERR_*`) and fail closed without silent fallbacks.
- **Verification**:
  - Rust suite (13 tests): 13 passed, 0 failed, 0 warnings.
  - Python suite (13 tests): 13 passed, 0 failed.
- **Handoff**: T-02931 (Documentation).
