# T-03362 Verification Output: Agent Loop Hardening — recovery & validation

- Date: 2026-11-06
- Subsystem: Phase 3 — AI Control Plane (Pillar C Spine) / Agent Loop Hardening / recovery & validation (T-03353..T-03362)
- Status: ALL RELEVANT SUITES PASSED

| Suite | Result |
|---|---|
| Recovery suites (scaffold, impl, unit, integration, security, hardening) | 41 passed, 1395 deselected, 1 warning in 25.97s |
| CI suite #34 `agent_loop_battery` | 527 passed, 1 skipped, 908 deselected, 1 warning in 128.31s (0:02:08) |

## Full aiosh-mcp suite, every failure classified (release tests excluded)
```
137 failed, 1273 passed, 5 skipped, 21 deselected, 5 warnings in 156.90s (0:02:36)
tests=1415 failures=137 errors=0 skipped=5
missing-Rust-binary failures: 136
other failures: ['tests.test_runbook_config_integration::test_integration_dynamic_session_capping_via_env :: assert True is False']
```
Unchanged baseline: 136 tests need the unbuilt Rust `aiosh-mcp.exe` (`WinError 2`), and one known order-dependent flake.

## Proof-of-Restraint
```
C1: PASS
C2: PASS
C3: PASS
C4: PASS
C5: PASS
C6: PASS
CONFORMANT: C1..C6 PASS
demo_por.py (exit 0): verdict   : PROVABLY_RESTRAINED
PASS: unused grant proved PROVABLY_RESTRAINED; post-anchor tamper (delete + re-chain) REJECTED.
```
The `VERIFY_FAILED: HEAD_HASH_MISMATCH` line in the demo output is the expected rejection of the tampered chain.

## Epic summary (T-03353..T-03362, PRs #469..#478)
- Shipped: `validate_ring` / `recover_orphans`, MCP `aios_agent_loop_validate` / `aios_agent_loop_recover`, CLI `validate-ring` / `recover`,
  `aios.agent_loop.failed` rows on breaker terminations, `orphaned_runs` in metrics.
- Independent security review (T-03359): 6 findings fixed, 2 High:
  - recovery could close a run that was still live in another process;
  - `write_audit_row` committed the caller's transaction early through `executescript()`, dropping the write lock.
- Hardening (T-03360): explicit `LOOPREC_ERR_WRITE` with partial results; validation deadline; `budget_invalid`.
  Shared fix: `grant_redeem` no longer overrides a caller's `busy_timeout`.
- Docs (T-03361): spec §5d with a runnable example executed by the drift test.
