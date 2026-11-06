# T-03392 Verification Output: Tool Registry & Taxonomy — CLI surface

- Date: 2026-11-06
- Subsystem: Phase 3 — AI Control Plane (Pillar C Spine) / Tool Registry & Taxonomy / CLI surface (T-03383..T-03392)
- Status: ALL RELEVANT SUITES PASSED

| Suite | Result |
|---|---|
| CI suite #35 `tool_registry` (data model, core service, CLI: scaffold, impl, unit, integration, security, hardening, doc) | 361 passed, 1 skipped, 1437 deselected, 1 warning in 37.30s |
| CI suite #34 `agent_loop_battery` | 557 passed, 1 skipped, 1241 deselected, 1 warning in 113.36s (0:01:53) |
| `tools/test_ci_suites.py` | PASS: ci_suites unit tests (W1..W7) |

The one skip is the export symlink test. This Windows account cannot create symlinks; the test runs where they are permitted.

## Full aiosh-mcp suite, every failure classified (release tests excluded)
```
137 failed, 1633 passed, 6 skipped, 23 deselected, 5 warnings in 187.92s (0:03:07)
tests=1776 failures=137 errors=0 skipped=6
missing-Rust-binary failures: 136
other failures: ['tests.test_runbook_config_integration::test_integration_dynamic_session_capping_via_env :: assert True is False']
```
Unchanged baseline. Disk was 11 GB free with no backup zips left behind.

## Proof-of-Restraint
```
CONFORMANT: C1..C6 PASS
demo_por.py (exit 0): verdict   : PROVABLY_RESTRAINED
PASS: unused grant proved PROVABLY_RESTRAINED; post-anchor tamper (delete + re-chain) REJECTED.
```

## Epic summary (T-03383..T-03392, PRs #502..#511)
- Shipped: `aiosh-tool-registry` / `python -m aiosh_mcp.tool_registry_cli`, a read-only operator CLI with five subcommands:
  - `list`, `get`, `decide`;
  - `export` (atomic, ≤ 4 MiB);
  - `check` (exit code for scripts).

  Also documented in operator doc §6c, with every documented command executed by the doc test.
- Independent review (T-03389) fixed:
  - a Windows closed-pipe crash (rc 120);
  - a cp1252 crash after a successful export;
  - terminal-escape injection through usage errors;
  - a crash with no stdout;
  - C1, separator and bidi-mark sanitiser gaps;
  - errors written to stdout;
  - temp-file leaks, including an fd leak found while testing.
- Hardening (T-03390): Ctrl-C → exit 130 with no traceback; real `--help`.
- Incidents: GitHub push failures ("fatal error in commit_refs") were retried until they succeeded. A stale local `main` caused an add/add
  conflict on #505, resolved by merging `origin/main`. The ship script now refuses a branch not based on `origin/main`.
