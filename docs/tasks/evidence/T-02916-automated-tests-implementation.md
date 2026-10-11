# T-02916 — Compliance Mapping / Automated Tests: Implementation

**Task**: T-02916 (Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / automated tests: Implementation)
**Depends on**: T-02915 (Scaffold — `docs/tasks/evidence/T-02915-automated-tests-scaffold.md`)
**Specification**: `docs/tasks/evidence/T-02914-spec.md`
**Date**: 2026-10-11
**Status**: COMPLETE — Minimal working behavior for all 10 automated test vectors implemented and verified across both Rust and Python substrates.

---

## 1. Implementation Overview

Implemented formal verification vectors `AUTOCOMPLIANCE1` through `AUTOCOMPLIANCE10` in:
- `code/aiosh-rust/aiosh-core/tests/test_compliance_automated.rs` (Rust substrate)
- `code/aiosh-mcp/tests/test_compliance_automated_smoke.py` (Python / MCP substrate)

All tests assert observable behavior, state transitions, security boundary enforcement, and cross-substrate parity.

---

## 2. Test Vectors Implemented

| Vector | Name | Coverage & Invariants Verified |
|---|---|---|
| **AUTOCOMPLIANCE1** | Lifecycle & Transitions | Full status lifecycle: `NonCompliant` -> `PartiallyCompliant` -> `Compliant`. Fails closed if transition to compliant lacks justification. |
| **AUTOCOMPLIANCE2** | Duplicate Rejection | Rejects duplicate primary key mappings (`COMPLIANCE_ERR_DUPLICATE_ID`); store remains untouched. |
| **AUTOCOMPLIANCE3** | Bounds Validation | Length limit on identifiers (> 64) and titles (> 128); character set hygiene (rejection of control chars, null bytes, spaces). |
| **AUTOCOMPLIANCE4** | Precedence Ladder | Deterministic 4-level resolution: argument beats env; env beats file; file beats default. Exact source map reporting. |
| **AUTOCOMPLIANCE5** | Hygiene Predicate | Rejects directory traversal (`..`), null bytes, newlines, empty strings, and paths > 1024 bytes (`hygiene_ok`). |
| **AUTOCOMPLIANCE6** | Size Caps | Strict 64 KiB config file size cap (`MAX_CONFIG_FILE_BYTES`); rejects oversized files pre-parse with `COMPLIANCECONF_ERR_FILE_SIZE`. |
| **AUTOCOMPLIANCE7** | Audit Immutability | `audit_all_mutations` cannot be disabled; attempts to set `false` clamp safely to `true`. |
| **AUTOCOMPLIANCE8** | PEP Gating | `verify_pep_coverage` and `uncovered_pep_gates` verify gate mappings for PEP enforcement (Invariant I-2). |
| **AUTOCOMPLIANCE9** | Assessment Scoring | Statistical precision for compliance reporting: total, compliant, partially compliant, non-compliant, not applicable, percentage calculation, and gap listing. |
| **AUTOCOMPLIANCE10** | Atomic Persistence | Atomic file write / rename; round-trip deserialization; path traversal prevention in `validate_path`. |

---

## 3. Verification & Test Evidence

### Rust Substrate
```text
running 10 tests
test test_autocompliance1_lifecycle_and_transitions ... ok
test test_autocompliance2_duplicate_rejection ... ok
test test_autocompliance3_bounds_validation ... ok
test test_autocompliance4_precedence_ladder ... ok
test test_autocompliance5_hygiene_predicate ... ok
test test_autocompliance6_size_caps ... ok
test test_autocompliance7_audit_immutability ... ok
test test_autocompliance8_pep_gating ... ok
test test_autocompliance9_assessment_scoring ... ok
test test_autocompliance10_atomic_persistence ... ok

test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
```

### Python Substrate
```text
code/aiosh-mcp/tests/test_compliance_automated_smoke.py ..........       [ 11%]
code/aiosh-mcp/tests/test_compliance_config.py .......................   [ 37%]
code/aiosh-mcp/tests/test_compliance_integration.py .......              [ 44%]
code/aiosh-mcp/tests/test_compliance_surface.py ...........              [ 57%]
code/aiosh-mcp/tests/test_compliance_unit.py ........................... [ 87%]
...........                                                              [100%]

89 passed, 237 deselected in 34.04s
```
Zero regressions across all existing compliance suites.
