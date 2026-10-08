# T-02905 — Compliance Mapping / Configuration: Scaffold

**Task**: T-02905 (Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / configuration: Scaffold)
**Depends on**: T-02904 (Specification — `docs/tasks/evidence/T-02904-spec.md`)
**Date**: 2026-10-08
**Status**: COMPLETE — both substrates build/import with zero errors; new interfaces are typed,
wired, and referenced by live test stubs on both sides.

## 1. What was created

| File | Role |
|---|---|
| `code/aiosh-rust/aiosh-core/src/compliance_config.rs` | **[NEW]** Rust config module: `ComplianceConfig`, `ConfigSource`, `ResolvedConfig`, constants, bounds, error-code family, `Default`, and six typed method signatures |
| `code/aiosh-mcp/aiosh_mcp/compliance_config.py` | **[NEW]** Python mirror: same constants/bounds/error codes plus five typed function signatures |
| `code/aiosh-rust/aiosh-core/src/lib.rs` | **[EXTENDED]** `pub mod compliance_config;` + a `pub use` block (aliased — see §3) |
| `code/aiosh-mcp/tests/test_compliance_unit.py` | **[EXTENDED]** scaffold stub `test_config_scaffold_constants_match_spec` |

No existing behavior changed: no production call site was rewired, no store/audit/PEP semantics
were touched. This is additive scaffolding only.

## 2. Scaffold contract — what is real vs loud

Per the task instruction ("typed signatures only; bodies fail loudly"):

**Real (data/contract, needed for `#[serde(default)]` and for tests to assert against):**
- all constants and bounds: `MAX_CONFIG_FILE_BYTES = 64*1024` (spec §5.1),
  `DEFAULT_CONFIG_PATH = "docs/compliance_config.json"` (D-2), `ENV_COMPLIANCE_CONFIG`,
  `ENV_COMPLIANCE_MAP_PATH`, `DEFAULT/MIN/MAX_MAX_STORE_FILE_BYTES`, `DEFAULT/MIN/MAX_MAX_ENTRIES`,
  `MAX_CONFIG_PATH_LEN = 1024` (spec §4.3), and the six `COMPLIANCECONF_ERR_*` codes;
- `Default for ComplianceConfig` — mirrors spec §3.1 exactly, including
  `audit_all_mutations: true` (spec §5.4: must never default false);
- `default_config()` on the Python side — same reason.

**Loud (behavior, implemented in T-02906):**

| Rust | Python |
|---|---|
| `from_json` `to_json` `from_path` `from_env` `resolve` `validate` `hygiene_ok` → `unimplemented!("T-02906: …")` | `load_config` `from_env` `resolve` `validate` `hygiene_ok` → `NotImplementedError("T-02906: …")` |

Each stub message carries the implementing task id so an accidental call in T-02905/T-02906 fails
loudly and self-documents.

## 3. Wiring detail: aliasing to keep one export per identifier

`lib.rs` already re-exports `DEFAULT_MAX_STORE_FILE_BYTES`, `MIN_MAX_STORE_FILE_BYTES`,
`MAX_MAX_STORE_FILE_BYTES` and `MAX_CONFIG_FILE_BYTES` **bare** from `secret_config`
(`lib.rs:484-485`), and `MAX_CONFIG_FILE_BYTES` is also aliased from `threat_model_config`
(`lib.rs:514`) and `sandbox_config` (`lib.rs:391`). Re-exporting the same names a fourth time
unaliased would create an ambiguous glob/name conflict.

The new block therefore exports under compliance-scoped names, following the existing
`… as MAX_THREAT_CONFIG_FILE_BYTES` convention:

```
DEFAULT_CONFIG_PATH            as DEFAULT_COMPLIANCE_CONFIG_PATH
DEFAULT_MAX_STORE_FILE_BYTES   as DEFAULT_COMPLIANCE_MAX_STORE_FILE_BYTES
MIN_MAX_STORE_FILE_BYTES       as MIN_COMPLIANCE_MAX_STORE_FILE_BYTES
MAX_MAX_STORE_FILE_BYTES       as MAX_COMPLIANCE_MAX_STORE_FILE_BYTES
DEFAULT_MAX_ENTRIES            as DEFAULT_COMPLIANCE_MAX_ENTRIES
MIN_MAX_ENTRIES                as MIN_COMPLIANCE_MAX_ENTRIES
MAX_MAX_ENTRIES                as MAX_COMPLIANCE_MAX_ENTRIES
MAX_CONFIG_FILE_BYTES          as MAX_COMPLIANCE_CONFIG_FILE_BYTES
MAX_CONFIG_PATH_LEN            as MAX_COMPLIANCE_CONFIG_PATH_LEN
```
`ComplianceConfig`, `ConfigSource`, `ResolvedConfig`, `ENV_COMPLIANCE_CONFIG`,
`ENV_COMPLIANCE_MAP_PATH` and the six `COMPLIANCECONF_ERR_*` codes are exported bare — none of
them pre-existed (verified by grep before the edit).

## 4. Interface inventory (spec §2, scaffold state)

| Interface | Status |
|---|---|
| `DEFAULT_STORE_PATH`, `DEFAULT_COMPLIANCE_MAP_PATH`, `store_path()`, `validate_path()`, `MAX_COMPLIANCE_STORE_SIZE`, `MAX_COMPLIANCE_ENTRIES_CAPACITY`, `COMPLIANCESVC_ERR_*`, `_recorded_call`, `dispatch`, `commit`, `WRITE_ACTIONS`, `--path` flag | **[REUSED]** — untouched, cited in T-02904 §2 |
| `compliance_config.rs` / `compliance_config.py` + `ComplianceConfig`, `ConfigSource`, `ResolvedConfig`, `resolve()`, `from_env()`, `validate()`, `hygiene_ok()`, `load_config()` | **[NEW]** — this task |

## 5. Build & test evidence (captured this run)

**Rust**
```
$ cargo build -p aiosh-core
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 3m 25s
BUILD_EXIT=0

$ cargo test -p aiosh-core --lib compliance_config
running 3 tests
test compliance_config::tests::test_scaffold_constants_match_spec ... ok
test compliance_config::tests::test_scaffold_defaults_match_spec_3_1 ... ok
test compliance_config::tests::test_scaffold_unimplemented_fails_loudly - should panic ... ok
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 458 filtered out
TEST_EXIT=0

$ cargo test -p aiosh-core --lib compliance
test result: ok. 3 passed; 0 failed (458 filtered out)
RUST_EXIT=0
```

**Python**
```
$ PYTHONPATH=code/aiosh-mcp python3 -c "from aiosh_mcp import compliance_config"
import OK, defaults: {'version': '1.0.0', 'store_path': 'docs/compliance_map.json',
 'max_store_file_bytes': 1048576, 'max_entries': 1024, 'audit_all_queries': False,
 'audit_all_mutations': True}

$ python3 code/aiosh-mcp/tests/test_compliance_unit.py
[PASS] test_config_scaffold_constants_match_spec
ALL 34 T-02897 UNIT TESTS PASSED!

$ python3 -m pytest -q code/aiosh-mcp/tests/test_compliance_integration.py
6 passed in 37.51s

$ python3 code/aiosh-mcp/tests/test_compliance_surface.py
SURFACE_EXIT=0
```

## 6. Acceptance check

- [x] **Project builds/imports with zero errors** — `cargo build -p aiosh-core` exit 0 with no
      warnings; `from aiosh_mcp import compliance_config` succeeds.
- [x] **New interfaces exist and are referenced by at least one call site or test stub** —
      three Rust tests in `compliance_config.rs` exercise `Default`, the constants, and the
      loud-failure body; one Python test in `test_compliance_unit.py` asserts constants,
      defaults, error-code family, and that all five Python bodies raise `NotImplementedError`
      naming T-02906.
- [x] No pre-existing suite regressed: compliance unit 34/34, integration 6/6, surface exit 0,
      `cargo test --lib compliance` green.

## 7. Honest limitations

- `resolve()` / `from_env()` are **not** wired into `store_path()` or `cmd_compliance` yet — that
  is T-02906's job, and deliberately not half-done here, so the existing precedence behavior is
  byte-identical to before this task.
- The Python `default_config()` imports `DEFAULT_STORE_PATH` from `.compliance` lazily to avoid a
  circular import; if T-02906 wants module-level access it should invert the dependency instead
  of adding a second path constant.
- `ConfigSource::ConfigInvalid` and `config_invalid` are declared but unreachable until the
  resolver exists; they are part of the spec §4.2 surface, not dead code by accident.
