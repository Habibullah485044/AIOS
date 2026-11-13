# T-03432 Verification Output: Tool Registry & Taxonomy — security policy

- Date: 2026-11-13
- Subsystem: Phase 3 — AI Control Plane (Pillar C Spine) / Tool Registry & Taxonomy / security policy (T-03423..T-03432)
- Status: ALL RELEVANT SUITES PASSED

| Suite | Result |
|---|---|
| CI suite #35 `tool_registry` | 694 passed, 1 skipped, 1462 deselected, 1 warning in 120.39s |
| CI suite #34 `agent_loop_battery` (the agent loop consumes `evaluate(surface="agent_loop")`) | 558 passed, 1 skipped, 1598 deselected, 1 warning in 170.50s |
| Capability gate and its consumers (`model_backend`, `mcp_server_core`, `capability_redeem`, `policy_hardening`) | 432 passed, 1725 deselected, 1 warning in 85.29s |
| `tools/test_ci_suites.py` | PASS: ci_suites unit tests (W1..W7) |
| `tools/check_evidence.py` | PASS: evidence integrity criteria (E1..E4) |

## Full aiosh-mcp suite, every failure classified
```
137 failed, 2014 passed, 6 skipped, 5 warnings in 481.72s (0:08:01)
failures=137 missing-Rust-binary=136 known-baseline=1 other=0
```
- The 136 failures are the Rust debug binary, which is not built on this host (`FileNotFoundError` /
  `aiosh-mcp.exe must exist`).
- The known one is `test_runbook_config_integration::test_integration_dynamic_session_capping_via_env`.
- **No failure outside the baseline.**

## Proof-of-Restraint
```
CONFORMANT: C1..C6 PASS
demo_por.py: verdict   : PROVABLY_RESTRAINED
PASS: unused grant proved PROVABLY_RESTRAINED; post-anchor tamper (delete + re-chain) REJECTED.
```
This epic touched grants, the PEP and dispatch, so an entry was appended to `docs/proof-of-restraint/LOG.md`.

## Epic summary (PRs #542..#551)
| Task | Delivered |
|---|---|
| T-03423 research, T-03424 spec | Decisions D1–D6, invariants TOOLPOL-INV1..6 |
| T-03425 scaffold, T-03426 implementation | `tool_registry_policy`: one OR-only, fail-closed-iff-strict policy point for dispatch and the agent loop; attributed refusals; `policy_revision` |
| T-03427 unit | 40 tests (valid, invalid, boundary, failure), mutation-checked |
| T-03428 integration | MCP decide and the CLI `decide` show what dispatch enforces, via a pure `preview()` |
| T-03429 security | **Critical PoR I-2 fix:** six paths accepted any non-empty capability token. They now redeem a real PEP grant (`capability_redeem`) |
| T-03430 hardening | Bounded DB wait, size caps before DB access, envelope errors; race, lock and rollback tests |
| T-03431 documentation | Operator doc §6g with executed examples and stated limitations; drift test |
| T-03432 verification | This file |

## Security audit (standing rule)
- **Re-verification only:** no code changed in this task.
- **Every invariant is still pinned by a passing test:**
  - TOOLPOL-INV1..5: unit, integration and hardening suites;
  - the I-2 redeem-before-act on all six capability-token tools: `test_capability_redeem_security.py`;
  - the honest fail-closed audit row: `test_tool_registry_policy_hardening.py`.
- **Open, recorded and not a bypass** (no served caller acts on it): T-03429 F2. These are the advisory
  `aios_mcp_policy_evaluate`, and the Rust `recover_mcp_store` and Rust policy engine with their non-empty token checks.
