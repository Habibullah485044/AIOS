# T-03272 Verification Output: Agent Loop Hardening Data Model

## Test Execution Summary
- Date: 2026-10-30
- Subsystem: Phase 3 — AI Control Plane (Pillar C Spine) / Agent Loop Hardening / data model
- Status: ALL PASSED (35/35 tests, 0 failures)

```
============================= test session starts =============================
platform win32 -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\OBSESSION\Desktop\AIOS_MERGED\code\aiosh-mcp
configfile: pyproject.toml
plugins: anyio-4.14.2, hydra-core-1.3.7
collected 35 items

code\aiosh-mcp\tests\test_agent_loop_data_model_scaffold.py ....         [ 11%]
code\aiosh-mcp\tests\test_agent_loop_data_model_impl.py ...              [ 20%]
code\aiosh-mcp\tests\test_agent_loop_data_model_unit.py ................ [ 65%]
.....                                                                    [ 80%]
code\aiosh-mcp\tests\test_agent_loop_data_model_integration.py ...       [ 88%]
code\aiosh-mcp\tests\test_agent_loop_data_model_hardening.py ....        [100%]

============================= 35 passed in 6.06s ==============================
```

## Proof of Restraint Demonstration Output

```
AIOS - Proof of Restraint milestone demo (T-02892)
=== STEP 1 - normal activity + one shadow action, then mint a capability (unused) ===
minted grant gr_demo_untouched (single_use, NEVER redeemed)
row id 3 is a shadow pentest.nmap action an attacker will later delete

=== STEP 2 - anchor the audit ring (signed Ed25519 checkpoints) ===
start anchor: seq=1 ts=2026-10-07T12:00:00Z
end   anchor: seq=6 ts=2026-10-07T12:10:00Z head_hash=747c68dbbb7d72fe...

=== STEP 3 - generate a restraint proof for the unused grant ===
proof_id  : por_9f64b6efdf67a9ee6b92cb0c
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
reason : VERIFY_FAILED: HEAD_HASH_MISMATCH: chain tail != anchor head_hash
standalone CLI exit code: 1 (must be non-zero)

=== DEMO RESULT ===
PASS: unused grant proved PROVABLY_RESTRAINED; post-anchor tamper (delete + re-chain) REJECTED.
```
