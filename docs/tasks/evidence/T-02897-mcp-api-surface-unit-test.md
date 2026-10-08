# T-02897 — Compliance Mapping MCP/API Surface: Unit Test

**Task**: T-02897 (Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / MCP/API surface: Unit Test)
**Depends on**: T-02896 (Implementation)
**Date**: 2026-10-08
**Status**: DONE — new test file runs standalone (29/29, exit 0) and under pytest (29/29); fail-when-broken proven by 3 mutations; no regressions.

**Deliverable**: `code/aiosh-mcp/tests/test_compliance_unit.py` — 29 focused unit tests.

---

## 1. Coverage map (T-02897 instructions)

### Valid input (8 tests)

| Test | Observable assertion |
|---|---|
| `test_register_show_roundtrip_envelope` | Spec §3 envelope (`ok`, `action`, `mapping`), alias-canonicalized framework, default status, show returns identical persisted mapping |
| `test_register_onto_missing_store_keeps_baseline` | CLI parity: first register persists canonical baseline (4) + new entry; store file contains 5 ids |
| `test_read_actions_never_create_or_touch_store` | list/assess/check-pep work off the baseline; store file is **not** created |
| `test_init_creates_baseline_file_then_refuses` | init writes `version 1.0.0` + 4 mappings; second init raises `STORE_EXISTS` |
| `test_status_change_persists_to_store` | status envelope + the **file bytes** reflect the new status |
| `test_framework_and_status_aliases_canonicalize` | `NIST` → `nist_sp_800_53_rev5`, `partial` → `partially_compliant`, case-insensitive parses |
| `test_assess_report_math_and_filters` | counts, `gaps == ["REQ-1"]`, percentage `5/6*100`, empty framework → `100.0` |
| `test_check_pep_uncovered_gate_reported` | uncovered gate → `covered=False`, `uncovered_required == [gate]` |

### Invalid input (8 tests — every class of the spec §4 error table)

| Test | Error code asserted |
|---|---|
| `test_unknown_action_param_invalid` | `PARAM_INVALID` |
| `test_missing_required_params_param_invalid` | `PARAM_INVALID` for 8 missing-parameter shapes (show/status/check-pep/register ×5); store file never created |
| `test_unknown_enum_values_param_invalid` | `PARAM_INVALID` for unknown framework/status on register and list |
| `test_invalid_identifier_codes` | `COMPLIANCE_ERR_INVALID_ID` (space, slash, blank, non-ASCII dash) |
| `test_empty_target_ref_missing_substrate_ref` | `COMPLIANCE_ERR_MISSING_SUBSTRATE_REF` (not the generic `PARAM_INVALID` — T-02896 ordering fix) |
| `test_duplicate_id_rejected_store_unchanged` | `COMPLIANCE_ERR_DUPLICATE_ID` **and** store bytes unchanged after the failed write |
| `test_show_and_status_not_found` | `COMPLIANCESVC_ERR_NOT_FOUND` |
| `test_compliant_transition_requires_summary_or_reason` | `COMPLIANCE_ERR_BOUNDS_EXCEEDED`; reason unlocks the transition |

### Boundary values (9 tests — N accepted, N+1 rejected)

| Test | Boundary |
|---|---|
| `test_identifier_byte_length_boundary` | id 64 B ok / 65 B rejected; **byte** semantics proven (`é`×33 = 66 B rejected at 33 chars) |
| `test_title_byte_length_boundary_and_control_chars` | title 128 ok / 129 rejected; `\n` rejected even in-length; blank rejected |
| `test_text_length_boundary_and_control_char_rules` | text 2048 ok / 2049 rejected; `\n\r\t` allowed, NUL rejected |
| `test_threat_and_tag_count_boundary` | 16 threats + 16 tags ok / 17 rejected each |
| `test_catalog_capacity_boundary` | catalog 1023→1024 ok, 1025th rejected (direct, no file I/O) |
| `test_store_file_size_cap_boundary` | store of `MAX+1` bytes → `COMPLIANCESVC_ERR_FILE_SIZE` |
| `test_corrupt_store_parse_error` | invalid JSON → `COMPLIANCESVC_ERR_PARSE` |
| `test_path_validation_boundaries` | non-`.json`, bare `.json`, traversal, 17-component depth rejected; 16 accepted |
| `test_obj_to_snapshot_parse_errors` | missing fields / non-list mappings / non-object entry → `COMPLIANCESVC_ERR_PARSE` |

Plus `test_load_store_missing_file_is_io_error` (`COMPLIANCESVC_ERR_IO`),
`test_status_transitions_follow_rust_fallback` (Rust `_ => true` parity) and
`test_pep_coverage_exact_rules` (pep_gate + ref + compliant|partial only).

### Primary failure mode (1 test)

`test_primary_ungranted_write_refused_store_untouched` — an ungranted
`register` through the real `aios_compliance` tool must be refused with
`gate == "pep"`, must leave **no store file** (fail-closed), and must write
exactly one `outcome="refused"` audit row. Reads stay available without a
grant (the second half of the test).

---

## 2. Acceptance evidence

### "New test file runs standalone and passes"

```
$ python3 code/aiosh-mcp/tests/test_compliance_unit.py
[PASS] test_register_show_roundtrip_envelope
... (29 lines) ...
ALL 29 T-02897 UNIT TESTS PASSED!
exit=0
```

Also collectable by pytest (same functions, no duplication):

```
$ python3 -m pytest code/aiosh-mcp/tests/test_compliance_unit.py -q
29 passed in 1.83s
```

### "Negative cases are asserted, not just happy path"

17 of 29 tests are negative/boundary (every `expect_error(...)` call asserts
the exact spec §4 code via `startswith("CODE: ")`), and the primary-failure
test asserts refusal + untouched store + audit row.

### "Confirm it fails when the feature is broken" (mutation proof)

Each mutation was applied byte-safely, the file run, and the source restored
byte-identical immediately (`git status` clean afterwards):

| Mutation | Source | Result |
|---|---|---|
| A — register no longer persists (`save_store` dropped) | `compliance.py` | **exit=1, 6 tests fail** (roundtrip, baseline-keeps, status-persists, assess math, duplicate-file-unchanged, transition guard) |
| B — identifier validation disabled (early return) | `compliance.py` | **exit=1, 2 tests fail** (invalid-id codes, byte-length boundary) |
| C — PEP gate disabled (`require_grant=False`) | `server.py` | **exit=1, 1 test fails** — the primary-failure test itself |

---

## 3. No regression (touched-module suites, re-run after final edit)

| Suite | Result |
|---|---|
| `test_compliance_surface.py` + `test_compliance_unit.py` together (env isolation check) | **40 passed** |
| PoR conformance battery `tools/test_por_conformance_suites.py` | **CONFORMANT: C1..C6 PASS** |
| PoR pytest battery `-k por` | **79 passed, 1 skipped, 197 deselected** |
| PEP decision + classifier smokes | **7 passed** |

The new file adds no source changes — only the test file itself; env vars
(`AIOSH_COMPLIANCE_MAP_PATH`, `AIOSH_HOME`) are set/restored per test via
context managers, verified by the combined 40-test run.

---

## 4. Acceptance checklist

- [x] **New test file runs standalone and passes** — `python3 .../test_compliance_unit.py` → 29/29, exit 0; pytest → 29 passed.
- [x] **Negative cases are asserted, not just happy path** — 17 negative/boundary tests, exact error codes from the spec §4 table.
- [x] Valid input, invalid input, boundary values, primary failure mode all covered (§1).
- [x] Fail-when-broken confirmed: 3 mutations → exit 1 each (§2).
- [x] Observable behavior only: return envelopes, store file bytes, audit rows — no internal call/attribute assertions.
- [x] Existing smoke suites for touched modules: no regression (§3).
