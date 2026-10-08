# T-02906 — Compliance Mapping / Configuration: Implementation

**Task**: T-02906 (Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / configuration: Implementation)
**Depends on**: T-02905 (Scaffold — `docs/tasks/evidence/T-02905-configuration-scaffold.md`)
**Contract**: T-02904 spec — `docs/tasks/evidence/T-02904-spec.md`
**Date**: 2026-10-08
**Status**: COMPLETE — test-first; both substrates implement the 4-level ladder; the F-3
cross-substrate divergence is fixed and proven end-to-end.

## 1. Changed files

| File | Change |
|---|---|
| `code/aiosh-mcp/aiosh_mcp/compliance_config.py` | 5 loud stubs → real bodies: `hygiene_ok`, `validate`, `_read_raw`, `load_config`, `from_env`, `resolve` |
| `code/aiosh-rust/aiosh-core/src/compliance_config.rs` | 7 `unimplemented!` → real bodies: `from_json`, `to_json`, `from_path`, `from_env`, `resolve`, `validate`, `hygiene_ok`, plus new `clamped()` / `field_names()` |
| `code/aiosh-rust/aiosh-cli/src/main.rs` | `cmd_compliance` now resolves the store through the ladder instead of `--path`-or-constant |
| `code/aiosh-mcp/aiosh_mcp/compliance.py` | `store_path()` now delegates to `compliance_config.resolve()` |
| `code/aiosh-mcp/tests/test_compliance_unit.py` | 4 new failing-first tests; scaffold loud-failure assertion flipped (bodies now exist) |

No new dependencies. No audit/PEP invariant touched: `_recorded_call`, `dispatch`, `commit` and
`WRITE_ACTIONS` are unchanged, so every consequential action still writes exactly one audit row.

## 2. Test-first evidence

The four tests were written **before** the implementation and confirmed red:

```
$ python3 code/aiosh-mcp/tests/test_compliance_unit.py     # BEFORE implementing
[FAIL] test_config_precedence_ladder_argument_env_file_default: NotImplementedError: T-02906: aiosh_mcp.compliance_config.resolve
[FAIL] test_config_env_hygiene_rejected_not_applied: NotImplementedError: T-02906: aiosh_mcp.compliance_config.resolve
[FAIL] test_config_malformed_file_fails_closed: AssertionError: T-02906: aiosh_mcp.compliance_config.load_config
[FAIL] test_config_bounds_clamp_and_mutations_audit_forced_true: NotImplementedError: T-02906: aiosh_mcp.compliance_config.validate
4/38 FAILED
```

After implementing:

```
$ python3 code/aiosh-mcp/tests/test_compliance_unit.py
ALL 38 T-02897 UNIT TESTS PASSED!
```

Two fixes surfaced by the red run (recorded honestly):
1. The T-02905 scaffold test asserted every body raises `NotImplementedError`. Once T-02906
   implemented them that assertion was obsolete — flipped to assert the bodies are callable and
   that `hygiene_ok` is total. The scaffold's *contract* (constants/defaults match spec §3.1) is
   retained unchanged.
2. My first hygiene test put a literal NUL byte into `os.environ`, which CPython rejects with
   `ValueError: embedded null character` at *assignment* time — the test never reached the code
   under test. Replaced with `\u0001` (a control char that env allows), so the predicate is what
   gets exercised.

## 3. What was implemented (spec mapping)

### Precedence ladder (spec §3.2) — identical on both substrates

```
1. argument   --path <P>            (CLI only; strongest)
2. env        AIOSH_COMPLIANCE_MAP_PATH  → store_path
             AIOSH_COMPLIANCE_CONFIG    → config file location
3. file       docs/compliance_config.json (or the env/arg-config path)
4. default    docs/compliance_map.json
```

`resolve()` returns `{"config": {...}, "source": {key: origin}}` with `source` one of
`argument | env | file | default | env_invalid | config_invalid` (spec §3.3/§4.1).

### Hygiene predicate (spec §4.3, CWE-15) — `hygiene_ok()`
Non-empty after trim, no `..`, no control characters, `len <= 1024`. Total: returns `bool`,
never raises, on either substrate. A failing env value is **reported as `env_invalid` and not
applied** — the default store remains active, so a hostile `AIOSH_COMPLIANCE_MAP_PATH` can never
relocate the compliance store.

### Failure policy (spec §4.2 — T-02903 D-5)
- **Fail closed**: malformed JSON → `COMPLIANCECONF_ERR_PARSE`; file > 64 KiB →
  `COMPLIANCECONF_ERR_FILE_SIZE` (size checked *before* parsing, CWE-400); empty `version` /
  `store_path` → `COMPLIANCECONF_ERR_VALIDATION`.
- **Clamp (inert fields)**: `max_entries` → `[1, 4096]`, `max_store_file_bytes` →
  `[4096, 16 MiB]`, and `audit_all_mutations` is **forced `true`** (spec §5.4 — config can never
  disable mutation auditing).
- **Not an error**: missing config file → defaults (spec §4.2 last row).

### Substrate wiring
- **Rust `cmd_compliance`**: `--path`-or-constant replaced by
  `ComplianceConfig::resolve(arg_path, arg_config)`. A config-resolution error emits
  `{"code":2,"error":{"code":"CONFIG_ERROR",...}}` and **returns before any store op** — fail
  closed, never a silent fallback to the default store.
- **Python `store_path()`**: delegates to `compliance_config.resolve()["config"]["store_path"]`.
  Every load/save site still passes the result through `validate_path()`, so config can never
  become a second, weaker path gate (spec §4.3).

## 4. End-to-end proof of the F-3 fix

T-02903 F-3: the Rust CLI had **0 occurrences** of `AIOSH_COMPLIANCE_MAP_PATH`, so the two
substrates could disagree about which file was the authoritative compliance store.

```
$ compliance init --path $TD/env5.json ; register MAP-ENVONLY into it
env store count: 5
default store count: 4

# Rust CLI, env var only — NO --path:
$ AIOSH_COMPLIANCE_MAP_PATH=$TD/env5.json aiosh compliance list --json
5 True                     # count=5, contains MAP-ENVONLY
```
The Rust CLI now reads the same file the Python/MCP surface reads.

**Ladder + fail-closed, exercised on the real binary:**
```
$ AIOSH_COMPLIANCE_CONFIG=$TD/bad.json aiosh compliance list --json
{"code":2,"error":{"code":"CONFIG_ERROR",
 "message":"Invalid compliance configuration: COMPLIANCECONF_ERR_PARSE: key must be a string at line 1 column 2"}}
```

## 5. Test results (captured this run)

| Suite | Result |
|---|---|
| `test_compliance_unit.py` (standalone) | **ALL 38 PASSED** (34 pre-existing + 4 new) |
| `test_compliance_surface.py` | exit 0 |
| `test_compliance_integration.py` (registered `compliance_integration`) | **6 passed in 33.11s** |
| `cargo test -p aiosh-core --lib compliance_config` | **6 passed, 0 failed** |
| `cargo build` (whole workspace: core, cli, mcp, sandbox) | **exit 0**, 5m31s |
| full battery `python3 tools/ci_run.py` | see §7 |

Rust tests: `test_hygiene_predicate_matches_spec_4_3`,
`test_clamped_bounds_and_audit_forced_true`, `test_malformed_and_missing_config_paths`,
`test_json_roundtrip_happy`, plus the two retained scaffold tests.

## 6. Invariants checked

- **One audit row per consequential action** — `WRITE_ACTIONS` still `("register","status",
  "init")`; no new MCP action was added in this task (that is T-02908 Integration scope), so the
  gating matrix is untouched. `_recorded_call` / `dispatch` / `commit` unmodified.
- **Reads never create the store** — `store_path()` is a pure resolver; it does not create the
  config file or the store.
- **`--path` still strongest** — an explicit argument overrides env and file (asserted).
- **No new dependencies** — `serde`/`serde_json` (Rust) and stdlib `json`/`os` (Python) only.

## 7. Full battery

Launched as the definitive gate; the captured summary is appended below.

### 7.1 A regression I introduced, caught by the registered gate (recorded honestly)

The first full battery run failed at suite 0:

```
FAIL: rust_smoke (exit 101)
test compliance_cli_tests::test_compliance_cli_path_validation ... FAILED
test result: FAILED. 65 passed; 1 failed
```

**Root cause — mine, not pre-existing.** I had applied the env hygiene predicate to the
**explicit `--path` argument** as well. `cmd_compliance(&["list", "--path", "../map.json"])`
therefore failed to reach `validate_path()` at all: the bad argument was discarded and resolution
carried on with the default store, so the call returned **0 (success)** where the test (correctly)
requires **2 (refusal)**. Silently substituting a valid default for an operator's invalid explicit
argument converts a *refusal into a success* — precisely the fail-open shape this project forbids.

**Fix (both substrates, same rule):** the hygiene predicate gates **environment** values only —
that is the CWE-15 surface the spec §4.3 gate was written for. An explicit operator argument is
applied unconditionally and flows on to `validate_path()`, which rejects it loudly.

```rust
// Level 1: explicit argument (strongest). Applied unconditionally:
// an operator-supplied `--path` must NOT be silently replaced by the
// default when it is invalid — it flows to `validate_path`.
```

**Regression guard added** so this cannot silently return: the Python precedence test now asserts
that `resolve(arg_path="../evil.json")` yields `store_path == "../evil.json"` with
`source == "argument"` **and** that the downstream `validate_path()` then rejects it with
`COMPLIANCESVC_ERR_PATH_TRAVERSAL`. The pre-existing Rust `test_compliance_cli_path_validation`
(4 path-hygiene cases) covers the Rust side.

**Note on detection:** `ci/rust_smoke.sh` pipes `cargo test` through `grep -E "test result"`, which
hides the failing test's name. I re-ran `cargo test` unfiltered to identify it. Not changed —
that is this suite's existing behaviour and out of scope here.

### 7.2 After the fix

| Check | Result |
|---|---|
| `cargo test -p aiosh-cli compliance_cli` | **4 passed, 0 failed** |
| `cargo test -p aiosh-core --lib compliance_config` | **6 passed, 0 failed** |
| `test_compliance_unit.py` | **ALL 38 PASSED** |
| full battery `python3 tools/ci_run.py` (run r2) | **31/31 PASS, exit 0** |

**Full battery (definitive run r2, `/tmp/aiosh-ci-results.json`, 2026-10-08T16:54:03Z):**
`all_pass: true`, `passed: 31`, `failed: 0`, `EXIT=0`, total 1061.66 s. Every registered suite
green, including `rust_smoke` (the suite that caught §7.1), `compliance_integration` (15.4 s),
`por_conformance` (11.1 s), `evidence_checker`, `task_ledger_unit`, `mcp_smoke`,
`classifier_smoke`, `toolchain_{cli,mcp}_smoke` and the `doc_*` / `evidence_*` groups.

Run r1 (before the §7.1 fix) failed at suite 0 with the `test_compliance_cli_path_validation`
regression described above; run r2 is the corrected, uninterrupted pass.
