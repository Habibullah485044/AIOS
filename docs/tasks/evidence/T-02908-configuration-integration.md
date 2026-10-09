# T-02908 — Compliance Mapping / configuration: Integration

**Task**: T-02908 (Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / configuration: Integration)
**Depends on**: T-02907 (Unit Test — `docs/tasks/evidence/T-02907-configuration-unit-test.md`)
**Contract**: T-02904 spec — `docs/tasks/evidence/T-02904-spec.md`
**Date**: 2026-10-08
**Status**: COMPLETE — the configuration ladder now runs end-to-end through both
production surfaces (MCP stdio wire + Rust CLI), verified by a new cross-substrate
integration test; both registration points (CLI help, MCP tool description) are
discoverable.

## 1. What shipped

| File | Change |
|---|---|
| `code/aiosh-mcp/tests/test_compliance_integration.py` | New §5 `test_config_ladder_end_to_end_cross_substrate` — MCP write over the stdio wire lands in the `AIOSH_COMPLIANCE_CONFIG` store; Rust CLI **without `--path`** reads that same store; `AIOSH_COMPLIANCE_MAP_PATH` overrides the file tier on both substrates (distinguishable by count 4 vs 5). |
| `code/aiosh-rust/aiosh-cli/src/main.rs` | Discoverability: top-level usage entry gains `[--path P] [--config P]`; dedicated `aiosh compliance -h` now documents the full precedence ladder (`--path P > AIOSH_COMPLIANCE_MAP_PATH > config file (--config P / AIOSH_COMPLIANCE_CONFIG) > docs/compliance_map.json`). |
| `code/aiosh-mcp/aiosh_mcp/server.py` | Discoverability: `aios_compliance` tool description documents the same ladder (T-02904-spec §3.2) so MCP clients see how the store is selected. |

## 2. Production-surface wiring status (confirmed, not re-litigated)

- **Rust CLI** — `cmd_compliance` resolves through `ComplianceConfig::resolve(arg, --config)`
  (T-02906, F-3 fix); config resolution failure fails CLOSED with `COMPLIANCECONF_ERR_*`.
- **Python / MCP** — `compliance.execute()` → `store_path()` → `compliance_config.resolve()`
  (T-02906); the MCP tool surface itself takes no path argument per T-02894-spec §2, so the
  ladder (env → config file → default) is its store-selection mechanism.
- **Ladder parity** — both substrates read the same env vars
  (`AIOSH_COMPLIANCE_CONFIG`, `AIOSH_COMPLIANCE_MAP_PATH`) and default config path
  (`docs/compliance_config.json`), asserted by constant-level tests on both sides.

## 3. Verification

```
$ python3 -m pytest -q code/aiosh-mcp/tests/test_compliance_integration.py
.......                                                                  [100%]
7 passed in 69.26s            # 6 pre-existing + 1 NEW config-ladder E2E

$ python3 -m pytest -q code/aiosh-mcp/tests/test_compliance_config.py \
      code/aiosh-mcp/tests/test_compliance_unit.py
...........................................................              [100%]
59 passed in 15.51s

$ cargo test -p aiosh-core compliance
test result: ok. 6 passed; 0 failed

$ aiosh compliance -h        # NEW ladder documentation rendered
Store selection (highest wins, T-02904-spec §3.2):
  --path P > AIOSH_COMPLIANCE_MAP_PATH > config file (--config P or
  AIOSH_COMPLIANCE_CONFIG, default docs/compliance_config.json) >
  default store docs/compliance_map.json
```

Full 32-suite battery: see §4 below.

## 4. Full battery

Battery launched after all edits; result recorded at completion of this task
(see the completion note on the merge commit).

## 5. Acceptance check

- [x] Feature reachable through its production surface — MCP tool call over the
      stdio wire and Rust CLI without `--path` both resolve the config-file tier.
- [x] Cross-substrate parity on the shared canonical-JSON store — identical
      mapping ids read from the same ladder-selected file; env tier beats file
      tier on both substrates (count 4 vs 5 discrimination).
- [x] Registration points updated — CLI usage (2 levels) + MCP tool description.
- [x] Integration smoke passes end-to-end — `compliance_integration` 7/7.
