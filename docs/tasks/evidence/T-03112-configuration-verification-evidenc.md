# Milestone Verification & Security Audit Evidence: MCP Server Core Configuration (T-03112)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / configuration
- **Target**: Milestone closeout for configuration (T-03103..T-03112)
- **Status**: PASSED
- **Certifications**: MCPCFG-INV1..MCPCFG-INV8, PoR Invariant I-2

---

## 1. Test Suite Execution Battery

### 1.1 Python Configuration Test Battery
`python -m pytest code/aiosh-mcp/tests/test_mcp_server_core_config_unit.py code/aiosh-mcp/tests/test_mcp_server_core_config_integration.py`
```
============================= test session starts =============================
collected 7 items

code/aiosh-mcp/tests/test_mcp_server_core_config_unit.py ....            [ 57%]
code/aiosh-mcp/tests/test_mcp_server_core_config_integration.py ...      [100%]

============================== 7 passed in 2.53s ==============================
```

### 1.2 Rust Core Configuration Battery
`cargo test --manifest-path code/aiosh-rust/Cargo.toml --test test_mcp_server_core_config_unit`
```
running 4 tests
test test_unit_case1_valid_config ... ok
test test_unit_case2_invalid_config ... ok
test test_unit_case3_boundary_values ... ok
test test_unit_case4_primary_failure_modes ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.41s
```

### 1.3 Proof of Restraint Conformance Smoke (`tools/demo_por.py`)
```
AIOS — Proof of Restraint milestone demo (T-02892)
=== STEP 1 — normal activity + one shadow action, then mint a capability (unused) ===
minted grant gr_demo_untouched (single_use, NEVER redeemed)
=== STEP 2 — anchor the audit ring (signed Ed25519 checkpoints) ===
=== STEP 3 — generate a restraint proof for the unused grant ===
proof_id  : por_646c58f2422a32b7dea52e8f
verdict   : PROVABLY_RESTRAINED
=== STEP 4 — verify with the standalone verifier (zero-database) ===
valid  : True
=== STEP 5 — TAMPER: delete the shadow row and re-chain the ring ===
=== STEP 5b — the attacker presents a freshly generated proof ===
valid  : False
reason : VERIFY_FAILED: HEAD_HASH_MISMATCH
=== DEMO RESULT ===
PASS: unused grant proved PROVABLY_RESTRAINED; post-anchor tamper (delete + re-chain) REJECTED.
```

---

## 2. Invariant & Security Audit Summary

1. **MCPCFG-INV1 (Path Sanitation)**:
   - Evaluated across POSIX and Windows components. Reject empty strings, NUL bytes (`\0`), and directory traversal components (`..`).
2. **MCPCFG-INV2 (Session Capacity Bounds)**:
   - `max_active_sessions` strictly bounded to `[1, 512]`.
3. **MCPCFG-INV3..4 (Timeout Invariants)**:
   - `session_idle_timeout_seconds` in `[60, 86400]` and `default_execution_timeout_seconds` in `[1, 300]`.
4. **MCPCFG-INV5..6 (Resource Limits)**:
   - `max_arguments_size_bytes` in `[1 KiB, 10 MiB]` and `max_tools_count` in `[1, 1024]`.
5. **MCPCFG-INV7 (Admin Capability Enforcement)**:
   - In accordance with PoR Invariant I-2, all administrative configuration mutations require capability grant token redemption. Read/validate tools are strictly non-mutating.
6. **MCPCFG-INV8 (Atomic Persistence)**:
   - Write-to-temp and atomic rename prevents file corruption; temp files are cleaned up on error.
7. **Audit Log Update**:
   - Logged milestone closeout in `docs/proof-of-restraint/LOG.md`.
