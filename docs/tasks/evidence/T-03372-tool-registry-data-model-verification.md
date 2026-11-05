# T-03372 Verification Output: Tool Registry & Taxonomy — data model

- Date: 2026-11-06
- Subsystem: Phase 3 — AI Control Plane (Pillar C Spine) / Tool Registry & Taxonomy / data model (T-03363..T-03372)
- Status: ALL RELEVANT SUITES PASSED

| Suite | Result |
|---|---|
| CI suite #35 `tool_registry` (scaffold, impl, unit, integration, security, hardening, doc) | 123 passed, 1437 deselected, 1 warning in 16.62s |
| CI suite #34 `agent_loop_battery` | 538 passed, 1 skipped, 1021 deselected, 1 warning in 107.65s (0:01:47) |
| `tools/test_ci_suites.py` (35 suites, frozen order) | PASS: ci_suites unit tests (W1..W7) |

## Full aiosh-mcp suite, every failure classified (release tests excluded)
```
137 failed, 1397 passed, 5 skipped, 21 deselected, 5 warnings in 156.54s (0:02:36)
tests=1539 failures=137 errors=0 skipped=5
missing-Rust-binary failures: 136
other failures: ['tests.test_runbook_config_integration::test_integration_dynamic_session_capping_via_env :: assert True is False']
```
Unchanged baseline: 136 tests need the unbuilt Rust `aiosh-mcp.exe`, and one known order-dependent flake. Disk stayed at 11 GB free;
no backup zips were left in the package (the self-inclusion bug was fixed in PR #487).

## Proof-of-Restraint
```
CONFORMANT: C1..C6 PASS
demo_por.py (exit 0): verdict   : PROVABLY_RESTRAINED
PASS: unused grant proved PROVABLY_RESTRAINED; post-anchor tamper (delete + re-chain) REJECTED.
```

## Epic summary (T-03363..T-03372, PRs #479, #482..#486, #488..#491; fixes #480, #481, #487)
- Shipped: `tool_registry_data_model`:
  - a validated, immutable catalog of 20 entries;
  - a fail-closed unknown profile;
  - MCP annotations derived from entries;
  - read-only MCP tools `aios_tool_registry_list` / `aios_tool_registry_get`;
  - CI suite #35;
  - the operator doc `docs/SPEC-TOOL-REGISTRY-DATA-MODEL.md`.
- Research found two **security gaps in existing PEP code**, fixed in their own PRs:
  - Rust `tool_glob_match` had no dot boundary (#480);
  - the TS PEP ignored `scope.networks` (#481).
- Independent review (T-03369): 8 confirmed findings, 3 Medium:
  - fs.read seeded without its grant requirement;
  - offline pentest tools network-scoped;
  - entries could be weaker than the name rules.

  All are fixed or documented.
- Hardening (T-03370): a broken catalog no longer takes the 69-tool server down.
- Incident: `release.create_backup` zipped itself into an 11 GB file and filled the disk twice. Fixed in #487.
