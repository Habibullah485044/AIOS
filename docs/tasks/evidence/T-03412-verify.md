# T-03412 Verification Output: Tool Registry & Taxonomy — configuration

- Date: 2026-11-06
- Subsystem: Phase 3 — AI Control Plane (Pillar C Spine) / Tool Registry & Taxonomy / configuration (T-03403..T-03412)
- Status: ALL RELEVANT SUITES PASSED

| Suite | Result |
|---|---|
| CI suite #35 `tool_registry` | 504 passed, 1 skipped, 1437 deselected, 1 warning in 158.93s (0:02:38) |
| CI suite #34 `agent_loop_battery` (it covers the shared agent-loop path guard changed in T-03409) | 557 passed, 1 skipped, 1384 deselected, 1 warning in 315.03s (0:05:15) |
| `tools/test_ci_suites.py` | PASS: ci_suites unit tests (W1..W7) |

## Full aiosh-mcp suite, every failure classified (release tests excluded)
```
137 failed, 1776 passed, 6 skipped, 23 deselected, 5 warnings in 393.16s (0:06:33)
tests=1919 failures=137 errors=0 skipped=6
missing-Rust-binary failures: 136
other failures: ['tests.test_runbook_config_integration::test_integration_dynamic_session_capping_via_env :: assert True is False']
```
Unchanged baseline. Durations are about twice normal because a disk-size scan (`du`) was still running in the background. Disk was 12 GB free
with no backup zips left behind.

## Proof-of-Restraint
```
CONFORMANT: C1..C6 PASS
demo_por.py (exit 0): verdict   : PROVABLY_RESTRAINED
PASS: unused grant proved PROVABLY_RESTRAINED; post-anchor tamper (delete + re-chain) REJECTED.
```

## Epic summary (T-03403..T-03412, PRs #522..#531)
- Shipped:
  - `tool_registry_config`: mode, report line cap, sample cap;
  - argument / env / file / default sources, with the numbers in that order and a **strictest-wins** mode;
  - locked security keys; hardened bounded file reads; per-process resolution;
  - problems reported once on stderr and as codes in stats;
  - operator doc §6e.
- The independent review (T-03409) fixed:
  - an **SMB/NTLM leak** in the shared path guard (`\??\UNC\…`), which also protects the agent-loop config;
  - **five ways a malformed, unreadable, relocated or ambiguous config could silently drop a requested strict mode**;
  - consumer disagreement;
  - error-message disclosure in stats.
- Hardening (T-03410): a forced strict mode is now explained on stderr, and a default-location failure no longer discards env values.
