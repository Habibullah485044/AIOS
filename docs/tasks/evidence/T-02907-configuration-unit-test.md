# T-02907 — Compliance Mapping / Configuration: Unit Test

**Task**: T-02907 (Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / configuration: Unit Test)
**Depends on**: T-02906 (Implementation — `docs/tasks/evidence/T-02906-configuration-implementation.md`)
**Contract**: T-02904 spec — `docs/tasks/evidence/T-02904-spec.md`
**Date**: 2026-10-08
**Status**: COMPLETE — new test file runs standalone and passes (21/21); all negative cases
asserted; mutation-sensitivity proven for five distinct feature breakages.

## 1. What was added

| File | Change |
|---|---|
| `code/aiosh-mcp/tests/test_compliance_config.py` | **[NEW]** 21 focused unit tests for the configuration resolver |
| `tools/ci_suites.py` | **[EXTENDED]** registered `compliance_config_unit` as suite **index 31** (tail append — every pre-existing index stays stable) |
| `tools/test_ci_suites.py` | **[EXTENDED]** `CANONICAL_ORDER` + count `31 → 32` to admit the new suite |

Test-file style matches `test_compliance_unit.py`: no pytest dependency (a `main()` runner prints
`[PASS]`/`[FAIL]` per case), while pytest still collects every `test_*` function.

## 2. Coverage map (spec §, and the observable assertion)

| Area | Tests | What is asserted |
|---|---|---|
| **Valid input** | `test_defaults_match_spec_section_3_1`, `test_valid_config_file_supplies_values_with_file_source`, `test_unknown_config_keys_are_ignored_not_persisted` | resolved values *and* per-key `source`; foreign keys never leak into the config |
| **Precedence ladder (§3.2)** | `test_precedence_argument_beats_env_beats_file_beats_default`, `test_load_config_env_var_selects_file` | each level wins in turn, proven by `source` attribution; level 1 moves `store_path` **only** |
| **Invalid input** | `test_env_path_hygiene_rejects_traversal_and_control_chars`, `test_hygiene_ok_is_total_and_matches_predicate`, `test_non_object_config_root_fails_closed`, `test_non_object_config_argument_rejected` | six hostile env values → `env_invalid` + default retained; predicate is total on non-string inputs |
| **Primary failure mode (§4.2)** | `test_malformed_config_fails_closed_with_parse_code`, `test_malformed_config_does_not_let_reads_proceed_silently`, `test_missing_config_file_is_not_an_error`, `test_empty_or_missing_fields_fall_back_to_defaults` | malformed → `COMPLIANCECONF_ERR_PARSE` (never a silent default); absent file → defaults |
| **Boundary values (§3.1/§5)** | `test_max_entries_boundaries_clamp`, `test_max_store_file_bytes_boundaries_clamp`, `test_config_file_size_boundary_exact_cap_accepted`, `test_env_path_length_boundary` | `lo-1/lo/hi/hi+1` on both numeric knobs; config file at **exactly 64 KiB accepted, +1 rejected before parsing**; path length `1024` vs `1025` |
| **Security invariants (§5)** | `test_audit_all_mutations_cannot_be_disabled`, `test_bad_explicit_argument_reaches_validate_path_not_silently_defaulted`, `test_resolution_creates_no_files`, `test_store_path_resolver_agrees_with_load_store_default` | §5.4 forced `true` (incl. via file); §7.1 regression guard; reads create nothing; default agrees with `DEFAULT_STORE_PATH` |

## 3. Standalone run (acceptance criterion)

```
$ python3 code/aiosh-mcp/tests/test_compliance_config.py
[PASS] test_defaults_match_spec_section_3_1
... (21 cases) ...
[PASS] test_store_path_resolver_agrees_with_load_store_default
------------------------------------------------------------
ALL 21 T-02907 CONFIG UNIT TESTS PASSED!
EXIT=0

$ python3 -m pytest -q --no-header -p no:cacheprovider \
      code/aiosh-mcp/tests/test_compliance_config.py
.....................                                                    [100%]
21 passed in 0.32s
EXIT=0
```

One assertion of mine was wrong on first run and is recorded here for honesty: I had asserted
`source["max_entries"] == "file"` for a config file that only sets `store_path` — the correct
expectation is `default`. Fixed the *test*, not the implementation.

## 4. Mutation sensitivity — "fails when the feature is broken"

The task requires confirming the new tests actually fail when the feature is broken. Five
independent mutations were injected into `aiosh_mcp/compliance_config.py`, the file restored from
backup after each, and the suite re-run:

| # | Mutation (feature broken) | Result |
|---|---|---|
| **M1** | CWE-15 hygiene gate removed — hostile env value applied directly | **1/21 FAILED**: `test_env_path_hygiene_rejects_traversal_and_control_chars` |
| **M2** | Bounds clamp removed — out-of-bounds `max_entries` accepted verbatim | **1/21 FAILED**: `test_max_entries_boundaries_clamp` |
| **M3** | `audit_all_mutations` no longer forced `true` (spec §5.4) | **1/21 FAILED**: `test_audit_all_mutations_cannot_be_disabled` |
| **M4** | Malformed config swallowed → returns defaults instead of failing closed | **2/21 FAILED**: `test_malformed_config_fails_closed_with_parse_code`, `test_malformed_config_does_not_let_reads_proceed_silently` |
| **M5** | Explicit argument ignored (precedence inverted) | **2/21 FAILED**: `test_precedence_argument_beats_env_beats_file_beats_default`, `test_bad_explicit_argument_reaches_validate_path_not_silently_defaulted` |
| — | **Restored baseline** | **ALL 21 PASSED**; `git diff` on the module clean |

Every security-relevant behaviour has at least one test that dies without it.

## 5. Registry wiring

```
$ python3 tools/test_ci_suites.py
[+] W1 registry 20/20 == frozen canonical order; bash delegates to ci_run.py; scripts exist
[+] W2 pass record + derived log path
[+] W3 timeout/error force exit_code=null (even when caller passes an int)
[+] W4 all invalid inputs rejected naming the field
[+] W5 atomic write + JSON round-trip, no temp leftovers
[+] W6 failed write leaves no temp files
[+] W7 corrupted registry rejected at import (duplicate suite name in SUITES: 'rust_smoke')
PASS: ci_suites unit tests (W1..W7)
EXIT=0
```

Also green: `tools/test_ci_run.py` (exit 0), `tools/test_ci_service.py` (X1..X7 PASS),
`tools/test_ci_config.py` (3 tests OK). `ci_service` derives expectations from `SUITE_NAMES`, so
it self-adjusts to 32.

**Suite index 31** (tail append) — verified programmatically:
`31 ['python3','-m','pytest','-q','--no-header','-p','no:cacheprovider','code/aiosh-mcp/tests/test_compliance_config.py'] 900`, `total 32`.

## 6. Acceptance check

- [x] **New test file runs standalone and passes** — 21/21 via `main()` and 21/21 via pytest.
- [x] **Negative cases are asserted, not just happy path** — hostile env values, malformed JSON,
      non-object JSON root, non-object config argument, both boundary sides of both numeric knobs,
      the 64 KiB file cap ±1, path length 1024/1025, and the disabled-audit attempt.
- [x] Confirmed failing-when-broken by five injected mutations (§4).

## 7. Full battery

**Definitive run (r1, `/tmp/aiosh-ci-results.json`, 2026-10-08T17:14:43Z):**
`all_pass: true`, `passed: 32`, `failed: 0`, `EXIT=0`, total **935.7 s**.

| | |
|---|---|
| Total registered suites | **32** (31 pre-existing + `compliance_config_unit`) |
| New suite index / status / duration | **31 / pass / 1320 ms** |
| Failures | none |

All pre-existing suites stayed green alongside the new one — `rust_smoke`, `compliance_integration`,
`por_conformance`, `compliance_config_unit` (the new tail-append), `task_ledger_unit`,
`task_matrix_smoke`, `mcp_smoke`, `classifier_smoke`, `toolchain_{cli,mcp}_smoke`, the `doc_*` and
`evidence_*` groups, and the rest. This confirms the registry edit (`31 → 32` suites) did not
perturb any pre-existing index or their behaviour.
