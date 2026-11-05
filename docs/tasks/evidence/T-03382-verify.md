# T-03382 Verification Output: Tool Registry & Taxonomy — core service

- Date: 2026-11-06
- Subsystem: Phase 3 — AI Control Plane (Pillar C Spine) / Tool Registry & Taxonomy / core service (T-03373..T-03382)
- Status: ALL RELEVANT SUITES PASSED

| Suite | Result |
|---|---|
| CI suite #35 `tool_registry` (data model + core service: scaffold, impl, unit, integration, security, hardening, doc) | 287 passed, 1437 deselected, 1 warning in 27.02s |
| CI suite #34 `agent_loop_battery` (the agent-loop policy now consults the service) | 557 passed, 1 skipped, 1166 deselected, 1 warning in 113.76s (0:01:53) |
| `tools/test_ci_suites.py` | PASS: ci_suites unit tests (W1..W7) |

## Full aiosh-mcp suite, every failure classified (release tests excluded)
```
137 failed, 1559 passed, 5 skipped, 23 deselected, 5 warnings in 175.74s (0:02:55)
tests=1701 failures=137 errors=0 skipped=5
missing-Rust-binary failures: 136
other failures: ['tests.test_runbook_config_integration::test_integration_dynamic_session_capping_via_env :: assert True is False']
```
Unchanged baseline with the service wired into dispatch and the agent loop in **shadow** mode (TOOLSVC-INV2 holds suite-wide). Disk
was 11 GB free afterwards, with no backup zips in the package.

## Proof-of-Restraint
```
CONFORMANT: C1..C6 PASS
demo_por.py (exit 0): verdict   : PROVABLY_RESTRAINED
PASS: unused grant proved PROVABLY_RESTRAINED; post-anchor tamper (delete + re-chain) REJECTED.
```

## Epic summary (T-03373..T-03382, PRs #492..#501)
- Shipped:
  - `tool_registry_service`, a pure `decide()` (stricter-of-both, disagreement reporting) wired into `_dispatch.dispatch` and
    `agent_loop_policy.evaluate_step`;
  - shadow by default; opt-in strict only tightens and fails closed on typos or registry failure;
  - catalog coverage of **all 69 served tools** (71 entries).
- Independent review (T-03379), no loosening found; fixed:
  - a shadow-mode stderr flood that stalled calls on an undrained pipe;
  - strict mode silently disabled by a mistyped value;
  - the raw canonical name leaking into reports;
  - reversible sample hashes;
  - a stdout write when stderr is missing;
  - a failed singleton build being retried on every call.
- Limitations documented in the operator doc §6b: scope is not enforced, and about 45 tools bypass dispatch.
