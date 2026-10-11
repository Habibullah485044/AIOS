# T-02912 — Compliance Mapping / configuration: Verification & Evidence

**Task ID**: T-02912 (Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / configuration: Verification & Evidence)  
**Depends on**: T-02911 (Documentation — `docs/tasks/evidence/T-02911-configuration-documentation.md`)  
**Contract**: `docs/tasks/evidence/T-02904-spec.md`  
**Date**: 2026-10-11  
**Status**: VERIFIED & CLOSED — The Compliance Mapping configuration subsystem is fully verified, hardened, documented, and passing 100% green across both Python and Rust substrates.

---

## 1. Test Verification Summary

### 1.1 Python Suite (MCP Substrate)

```
$ python -m pytest code/aiosh-mcp/tests/test_compliance_config.py -v
============================= 23 passed in 2.52s ==============================

$ python -m pytest code/aiosh-mcp/tests/test_compliance_unit.py -q
...........................................                              [100%]
43 passed in 4.12s

$ python -m pytest code/aiosh-mcp/tests/test_compliance_integration.py -v
============================= 7 passed in 42.32s ==============================
```
**Total Python Tests**: 73 passed; 0 failed.

### 1.2 Rust Suite (Core / CLI Substrate)

```
$ cargo test -p aiosh-core --lib compliance_config
running 6 tests
test compliance_config::tests::test_clamped_bounds_and_audit_forced_true ... ok
test compliance_config::tests::test_hygiene_predicate_matches_spec_4_3 ... ok
test compliance_config::tests::test_json_roundtrip_happy ... ok
test compliance_config::tests::test_scaffold_constants_match_spec ... ok
test compliance_config::tests::test_scaffold_defaults_match_spec_3_1 ... ok
test compliance_config::tests::test_malformed_and_missing_config_paths ... ok

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 458 filtered out; finished in 0.07s
```

---

## 2. Invariant & Proof-of-Restraint Verification

1. **Precedence Ladder Invariant**:
   - Level 1 `--path` overrides all others.
   - Level 2 `AIOSH_COMPLIANCE_MAP_PATH` overrides config file.
   - Level 3 `--config` / `AIOSH_COMPLIANCE_CONFIG` overrides default config file.
   - Level 4 fallback to `docs/compliance_map.json`.
   - Verified cross-substrate across Python MCP and Rust CLI.

2. **Proof-of-Restraint [PoR] Invariant I-2**:
   - Configuration resolution is strictly read-only and emits zero unauthorized mutations.
   - Any state-changing actions (`add`, `update`, `delete`, `status`) strictly require valid capability tokens redeemed at dispatch.

3. **Audit Immutability**:
   - `audit_all_mutations` cannot be disabled; attempts to set `false` are clamped to `true`.

---

## 3. Milestone Completion

This task completes the **Compliance Mapping / configuration** slice (tasks T-02903 through T-02912) of Phase 2.
All acceptance criteria are satisfied.
