# Verification Battery: AI Control Plane MCP Server Core Service (T-03082)

**Task ID**: T-03082 (Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / core service: Verification & Evidence)  
**Date**: 2026-10-17  
**Author**: Codebuff (Antigravity Autonomous Pair)  
**Status**: PASSED — All unit, integration, hardening, and Proof-of-Restraint conformance suites passed.

---

## 1. Rust Test Suite Output

```
Running tests\test_mcp_server_core_service_hardening.rs
test test_hardening_safe_dispatch_timeout_and_fault_tolerance ... ok
test test_hardening_prune_idle_and_terminated_sessions ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

Running tests\test_mcp_server_core_service_integration.rs
test test_integration_core_service_end_to_end ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

Running tests\test_mcp_server_core_service_scaffold.rs
test test_mcp_core_service_scaffold_types ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

Running tests\test_mcp_server_core_service_unit.rs
test test_unit_case2_invalid_input_and_unauthorized_dispatch ... ok
test test_unit_case4_primary_failure_mode_missing_tool_and_envelope ... ok
test test_unit_case1_valid_tool_and_session_lifecycle ... ok
test test_unit_case3_boundary_values_capacity_and_eviction ... ok
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

## 2. Python Test Suite Output

```
============================= test session starts =============================
platform win32 -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\OBSESSION\Desktop\AIOS_MERGED\code\aiosh-mcp
configfile: pyproject.toml
plugins: anyio-4.14.2
collected 9 items

code\aiosh-mcp\tests\test_mcp_server_core_service_scaffold.py .          [ 11%]
code\aiosh-mcp\tests\test_mcp_server_core_service_unit.py ....           [ 55%]
code\aiosh-mcp\tests\test_mcp_server_core_service_integration.py ..      [ 77%]
code\aiosh-mcp\tests\test_mcp_server_core_service_hardening.py ..        [100%]

============================== 9 passed in 3.51s ==============================
```

## 3. Proof-of-Restraint (PoR) Conformance Demo Output

```
AIOS - Proof of Restraint milestone demo (T-02892)
sandbox: ...

=== STEP 1 - normal activity + one shadow action, then mint a capability (unused) ===
minted grant gr_demo_untouched (single_use, NEVER redeemed)
row id 3 is a shadow pentest.nmap action an attacker will later delete

=== STEP 2 - anchor the audit ring (signed Ed25519 checkpoints) ===
start anchor: seq=1 ts=2026-10-07T12:00:00Z
end   anchor: seq=6 ts=2026-10-07T12:10:00Z head_hash=747c68dbbb7d72fe...

=== STEP 3 - generate a restraint proof for the unused grant ===
proof_id  : por_612ed1b4185d53136237706a
verdict   : PROVABLY_RESTRAINED
grant     : gr_demo_untouched redeemed_at=None
live rows : seq 1..6

=== STEP 4 - verify with the standalone verifier (zero-database) ===
valid  : True
reason : None
checks : {"anchor_bounds": true, "anchor_keys": true, "anchor_sigs": true, "bloom_exclusion": true, "grant": true, "live_chain": true, "schema": true}
standalone CLI exit code: 0

=== STEP 5 - TAMPER: delete the shadow row and re-chain the ring ===
chain check before tamper: {'ok': True, 'checked': 6, 'broken_at': None, 'anchor': '0000000000000000000000000000000000000000000000000000000000000000'}
deleted row id 3 and re-chained all hashes
chain check after tamper : {'ok': True, 'checked': 5, 'broken_at': None, 'anchor': '0000000000000000000000000000000000000000000000000000000000000000'}  <- internally consistent again

=== STEP 5b - the attacker presents a freshly generated proof ===
valid  : False
reason : VERIFY_FAILED: HEAD_HASH_MISMATCH: chain tail ... != anchor head_hash ...
checks : {"anchor_bounds": true, "anchor_keys": true, "anchor_sigs": true, "bloom_exclusion": true, "grant": true, "live_chain": false, "schema": true}
standalone CLI exit code: 1 (must be non-zero)

=== DEMO RESULT ===
PASS: unused grant proved PROVABLY_RESTRAINED; post-anchor tamper (delete + re-chain) REJECTED.
```
