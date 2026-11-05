# T-03368 Evidence: Tool Registry & Taxonomy — data model Integration

- Date: 2026-11-06
- Production surface: two read-only MCP tools registered in `aiosh_mcp/server.py` through
  `tool_registry_data_model.register_tool_registry_tools(mcp)`:
  - `aios_tool_registry_list(category?)`: the catalog, optionally filtered by a schema-enumerated category.
  - `aios_tool_registry_get(name)`: resolves a canonical or MCP name (1..256 chars). An unregistered name returns the
    **fail-closed** profile with `registered: false`.
  - Their `ToolAnnotations` are **derived from their own catalog entries** (`aios.tool_registry.list/get`, read-only,
    closed-world). No tool can change the catalog (TOOLREG-INV5).
- Discoverable: the live server now serves **69** tools (`tools/list`).
- CI: new suite **#35 `tool_registry`** (`pytest -k tool_registry code/aiosh-mcp/tests`) is appended at the tail, so existing
  indices are unchanged; `tools/test_ci_suites.py` pins 35 suites.

## Cross-substrate parity (`tests/test_tool_registry_data_model_integration.py`, 4 tests)
| Check | Result |
|---|---|
| stdio MCP: `list` = the catalog; `list(category=pentest)` only pentest; `get("aios_pentest_nmap")` registered; `get("pentest.newthing")` fail-closed with network scope; a bad category and a 300-char name are rejected by the schema | pass |
| Every TS `ToolClass` value (parsed from `aiosh-cli/src/types.ts`) is a `Category` | pass |
| TS `isIrreversible` (built `dist/pep.js`, via node) agrees with the catalog's `irreversible` for **every** entry | pass, 0 disagreements |
| Served-tool coverage: the catalog covers **17 of 69** served tools; 52 are untracked and listed, not failed (spec §3). Every agent-loop / registry / fs / process / audit / pentest alias in the catalog is really served. | tracked |

## Results
```
$ python -m pytest -q -p no:cacheprovider -k tool_registry code/aiosh-mcp/tests
99 passed, 1436 deselected, 1 warning in 8.81s
$ python tools/test_ci_suites.py   -> PASS: ci_suites unit tests (W1..W7)
$ python tools/test_ci_service.py  -> PASS: ci_service unit tests (X1..X7)
```
Closest existing MCP smoke selection (`mcp_smoke or server_tools or tools_list or test_mcp`, `not release`), compared per test
between this branch and `main`: **139 passed / 99 failed on both, identical failure sets**. All 99 are the known
missing-Rust-binary baseline.

## Incident during verification (fixed separately)
Without `not release`, that selection runs `test_release_mcp_smoke::test_create_backup_returns_path`.
`release.create_backup(target_path=".")` writes its zip *inside* the directory it is zipping, so the archive includes
itself. It grew to **10.9 GB** and filled the disk. I deleted the untracked test zips (6 files, created by tonight's runs),
and the self-inclusion bug is fixed in its own PR.
