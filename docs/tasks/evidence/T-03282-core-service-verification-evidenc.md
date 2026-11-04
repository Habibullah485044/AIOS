# T-03282 Verification Output: Agent Loop Hardening Core Service

- Date: 2026-11-05
- Subsystem: Phase 3 — AI Control Plane (Pillar C Spine) / Agent Loop Hardening / core service (T-03273..T-03282)
- Status: ALL RELEVANT SUITES PASSED

## Core service + affected data-model suites
```
tests\test_agent_loop_core_service_scaffold.py ...                       [  5%]
tests\test_agent_loop_core_service_impl.py ....                          [ 12%]
tests\test_agent_loop_core_service_unit.py ..................            [ 45%]
tests\test_agent_loop_core_service_integration.py .....                  [ 54%]
tests\test_agent_loop_core_service_security.py .........                 [ 70%]
tests\test_agent_loop_core_service_hardening.py .............            [ 94%]
tests\test_agent_loop_data_model_integration.py ...                      [100%]

============================= 55 passed in 4.76s ==============================
```

## All agent-loop suites (data model + core service)
```
87 passed, 909 deselected in 7.57s
```

## Proof-of-Restraint pytest suites (gate/redeem/anchoring/conformance)
```
19 passed, 4 warnings in 6.27s
```

## PoR conformance smoke (`python tools/test_por_conformance_suites.py`)
```
C1: PASS
C2: PASS
C3: PASS
C4: PASS
C5: PASS
C6: PASS
CONFORMANT: C1..C6 PASS
```

## PoR demo + anchor verification (`python tools/demo_por.py`)
```
verdict   : PROVABLY_RESTRAINED
reason : VERIFY_FAILED: HEAD_HASH_MISMATCH: chain tail 0923cab6d054b06cab240201eecf5027934325dc29c0160beeb42f35b52191e5 != anchor head_hash 
standalone CLI said: {"checks":{"anchor_bounds":true,"anchor_keys":true,"anchor_sigs":true,"bloom_exclusion":true,"grant":true,"live_chain":
```
The unused grant is proved restrained; after the post-anchor tamper the proof is rejected (`HEAD_HASH_MISMATCH`), as designed.

## Full aiosh-mcp baseline (release tests excluded)
822 passed, 137 failed, 4 skipped. 135 failures are `FileNotFoundError: [WinError 2]` launching the
unbuilt Rust binary `code/aiosh-rust/target/debug/aiosh-mcp.exe`; 1 is the binary-exists assertion; 1 is the
order-dependent `test_runbook_config_integration` flake (passes alone on this branch and on `main`). The same
binary-missing failures occur on `main`. `test_release_*smoke` were excluded because they write
`aios_backup_*.zip` archives into the working directory (one reached 6.3 GB and filled the disk).
