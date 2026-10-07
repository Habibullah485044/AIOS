# Task Evidence: T-02886 — Continuous Restraint Conformance: Unit Test

- **Task ID**: `T-02886`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / continuous restraint conformance (Component 6)
- **Date**: 2026-10-07
- **Invariants Verified**: `I-5` (Continuous Conformance Gate)

## Unit Test Verification Delivered

Created `code/aiosh-mcp/tests/test_por_conformance_meta.py` — meta-tests proving the CRCS harness itself is sound (a conformance gate is only trustworthy if its own structure cannot silently rot):

| Test | Assertion |
|---|---|
| `test_m1_battery_criteria_map_complete` | `CRITERIA == C1..C6`; every criterion maps to non-empty `test_*` node ids |
| `test_m2_mapped_nodes_resolve_to_real_tests` | every battery node id resolves to a callable test in the suite module (no phantom nodes) |
| `test_m3_no_orphaned_conformance_tests` | every `test_c*` in the suite is battery-mapped and vice versa (no unenforced conformance tests — the gate can't silently lose criteria) |
| `test_m4_runner_fail_closed_on_unmapped_criterion` | `run_criterion` returns `False` for unmapped/empty criteria |
| `test_m5_sandbox_isolation` | the conformance sandbox lives in a `por-conform-` temp `AIOSH_HOME`, never touches the real `audit.db`, and restores `AIOSH_HOME` on cleanup |
| `test_m6_contract_fixture_identifiers` | the F-* fixture identifiers of T-02883-spec.md §3 (`gr_conform_untouched`, `gr_conform_redeemed`, window ordering, forgery + TS-canonical helpers) exist in the suite |

Refactor accompanying this task: `conform_env` fixture split into a plain `_make_env()` factory + thin fixture wrapper, so the sandbox lifecycle is unit-testable without cross-module fixture coupling.

## Test Results
```
test_por_conformance_meta.py::test_m1_battery_criteria_map_complete PASSED
test_por_conformance_meta.py::test_m2_mapped_nodes_resolve_to_real_tests PASSED
test_por_conformance_meta.py::test_m3_no_orphaned_conformance_tests PASSED
test_por_conformance_meta.py::test_m4_runner_fail_closed_on_unmapped_criterion PASSED
test_por_conformance_meta.py::test_m5_sandbox_isolation PASSED
test_por_conformance_meta.py::test_m6_contract_fixture_identifiers PASSED
test_por_conformance.py (14 criteria tests)                          PASSED
============================= 20 passed in 5.92s ==============================
```

## Security Audit
- The gate cannot silently lose criteria: M3 fails if any conformance test is ever un-mapped from the CI battery.
- The gate cannot silently pass on infrastructure rot: M2 fails on phantom node ids.
- Sandbox isolation is now itself verified (M5), protecting the developer machine's real audit store during CI runs.
