# T-03402 Verification Output: Tool Registry & Taxonomy — API surface

- Date: 2026-11-06
- Subsystem: Phase 3 — AI Control Plane (Pillar C Spine) / Tool Registry & Taxonomy / API surface (T-03393..T-03402)
- Status: ALL RELEVANT SUITES PASSED

| Suite | Result |
|---|---|
| CI suite #35 `tool_registry` | 421 passed, 1 skipped, 1437 deselected, 1 warning in 39.56s |
| CI suite #34 `agent_loop_battery` | 557 passed, 1 skipped, 1301 deselected, 1 warning in 110.74s (0:01:50) |
| `tools/test_ci_suites.py` | PASS: ci_suites unit tests (W1..W7) |

## Full aiosh-mcp suite, every failure classified (release tests excluded)
```
137 failed, 1693 passed, 6 skipped, 23 deselected, 5 warnings in 187.09s (0:03:07)
tests=1836 failures=137 errors=0 skipped=6
missing-Rust-binary failures: 136
other failures: ['tests.test_runbook_config_integration::test_integration_dynamic_session_capping_via_env :: assert True is False']
```
Unchanged baseline with catalog annotations applied to every served tool (TOOLAPI-INV3: server enforcement untouched). Disk was 11 GB free with no
backup zips left behind.

## Proof-of-Restraint
```
CONFORMANT: C1..C6 PASS
demo_por.py (exit 0): verdict   : PROVABLY_RESTRAINED
PASS: unused grant proved PROVABLY_RESTRAINED; post-anchor tamper (delete + re-chain) REJECTED.
```

## Epic summary (T-03393..T-03402, PRs #512..#521)
- Shipped:
  - `aios_tool_registry_decide` and `aios_tool_registry_stats`;
  - `apply_catalog_annotations`: every served tool annotated (was 14 of 69), never relaxing, read-only only under a strict conjunction;
  - operator doc §6d.
- The independent audit (T-03399) read and probed all 40 tools first advertised read-only. **Two could burn single-use PEP grants without a
  client confirmation prompt** (`aios_restraint_prove` / `_verify` via `caller_grant_id`). Fixed in the catalog and by a structural rule: no
  grant, token or path argument may be read-only. Read-only went from 40 to 35, all verified.
- Hardening (T-03400): an unreadable tool schema can no longer abort server import.
- Follow-ups recorded: confine the path arguments of three tools to `$AIOSH_HOME`; bound the segment scans of `aios_audit_verify(full)` /
  `aios_audit_seen(exact)`.
