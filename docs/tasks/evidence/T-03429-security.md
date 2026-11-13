# T-03429 Security Review: Tool Registry & Taxonomy — security policy

- Date: 2026-11-13
- Scope:
  - `aiosh_mcp/tool_registry_policy.py`: `evaluate`, `preview`, `policy_revision`, `grant_reason_suffix`.
  - Its consumers: `_dispatch`, `agent_loop_policy`, and the MCP decide/stats tools plus the CLI.
  - Following the ledger's PEP and I-2 instructions, **every served MCP tool the catalog marks `requires_grant`**.
- Spec: [T-03424](T-03424-security-policy-specification.md). Previous: [T-03426](T-03426-security-policy-implementation.md),
  [T-03427](T-03427-security-policy-unit-test.md), [T-03428](T-03428-security-policy-integration.md).

## Findings
| # | Severity | Finding | Status |
|---|---|---|---|
| F1 | **Critical** | **PoR I-2 bypass.** Six state-changing paths behind five served MCP tools treated *any non-empty string* as a capability token. Nothing was redeemed, so the `pep_grants` table and the audit ring were never consulted (the bug class T-03279 F1 fixed for the agent loop). The tools: `aios_mcp_recovery_repair` (quarantines and rewrites a file), `aios_model_recover_config` (same), `aios_model_endpoint_register` and `model_backend_register` (mutate the model registry), `aios_model_complete` and `model_backend_complete` (outbound model calls). | **Fixed** (below) |
| F2 | Low | `aios_mcp_policy_evaluate` (advisory policy engine, Python and Rust) reports "capability token redeemed" for any non-empty token. No action consumes its verdict (grep: no caller of `_GLOBAL_POLICY_ENGINE` outside its module), so it is misleading wording, not a bypass. Rust `recover_mcp_store` has the same check but no caller outside its file and tests. | Recorded; the fix is to reuse `capability_redeem` semantics when these engines gain a real consumer |
| F3 | Info | `McpServerCoreService.dispatch_tool_call` gates `aios.admin.*` on a non-empty `grant_id` only, but executes nothing (returns a fixed "Executed …: ok" stub). | No state change; recorded |
| — | — | Tool registry policy itself: no bypass found (scenarios below). | — |

### F1 fix: redeem before act
- New `aiosh_mcp/capability_redeem.py` provides `redeem_capability(token, *, tool, command, target)`. It calls
  `audit_client.grant_redeem`, which requires:
  - the grant exists, is unexpired and unrevoked;
  - `scope.tools` covers the tool (and `scope.paths` the target when set);
  - a single-use grant is consumed atomically.

  It writes the `pep.capability.redeem` audit row. It **fails closed**: a missing DB, a lock timeout or any exception
  refuses the action. Tokens longer than 512 chars, or containing NUL, are refused before any DB access. Refusal
  reasons are secret-masked and bounded to 300 chars.
- All six check sites now call it, keeping their existing error codes and envelopes. Each tool redeems exactly once
  (the API handlers do not call a second token check downstream, so a single-use grant is not double-spent). The
  recovery paths redeem before touching the file.
- Tests that passed made-up tokens now get those ids minted as real, multi-use grants in an isolated `AIOSH_HOME`.
  This is `conftest._seeded_capabilities`, scoped to the model-backend and MCP-recovery modules.
- New `tests/test_capability_redeem_security.py` (25):
  - forged and malformed tokens are refused, including oversize, NUL, non-string and whitespace;
  - single-use is enforced, and an audit row is written;
  - wrong scope, revoked and expired grants are refused;
  - an unavailable DB fails closed;
  - the reason is masked;
  - each fixed tool refuses a forged token with **no state change** (file untouched, no backup created, registry
    unchanged, backend never called) and accepts a real grant.

  **Against the pre-fix code, 10 of these fail.** After the fix, all 25 pass.

## Abuse scenarios (tool registry policy)
| # | Scenario | Result |
|---|---|---|
| A1 | Caller passes `require_grant=False` to dodge a grant | OR-only: the caller can only add requirements (TOOLPOL-INV1; T-03427 grid) |
| A2 | Name tricks to reach a non-grant entry: case, padding, ZWSP, U+2024, fullwidth, `aios_anchor_create`, NUL, `..`, `/../` | Probed live in strict. Every variant is either the real canonical (grant) or unregistered (grant, D4). None resolved to a weaker entry |
| A3 | Non-string tool name (`None`, bytes, list, dict, 10 KB) | Never raises; grant-required in strict (T-03427) |
| A4 | Break the catalog or service to fail open | Fails closed iff strict was intended; even an unreadable mode assumes strict (TOOLPOL-INV4) |
| A5 | Downgrade the mode at runtime | Mode comes only from env/config, fixed per process; strict can only tighten (T-03409). No tool argument reaches it |
| A6 | Flood stderr or fill the disagreement log through the decide tool or CLI | `preview()` is pure; decide has its own counters (T-03399 F3); dispatch reporting is capped at `MAX_REPORT_LINES` |
| A7 | Inject text into a refusal reason | The suffix is fixed text plus a hex revision; the tool name is formatted as before |
| A8 | Spoof `policy_revision` / cache poisoning by `id()` reuse | The cache entry holds the catalog object (`hit[0] is cat`), so an id cannot be reused while cached; bounded at 8 |
| A9 | Revision collision to hide a catalog change | 64-bit truncated SHA-256 over the security fields; informational only, so nothing is enforced from it |
| A10 | Forge a capability token on a grant-required tool | F1: was possible on 5 tools, **now refused** |

## PEP gating and audit rows for state-changing paths
- The 25 served `requires_grant` tools were enumerated from `server.mcp`.
- 13 visibly call the PEP (`dispatch`/`_recorded_call`/gate helpers).
- The other 12 were traced by hand:
  - `aios_fs_read` and `aios_anchor_create` go through `_recorded_call` → `_dispatch.dispatch`.
  - The `aios_agent_loop_*` tools go through `PepCapabilityGate.redeem` (T-03279).
  - `aios_mcp_core_dispatch` is F3.
  - The six model-backend and recovery paths behind the remaining tools were F1, now `redeem_capability`.
- Every redemption writes a `pep.capability.redeem` audit row; dispatch refusals keep their existing row.

## PoR I-2 check (standing rule)
This task **changes six state-changing paths**. Each now redeems a capability grant before acting, and cannot execute
without one (`test_capability_redeem_security.py`). Redeem-before-act in dispatch (Gate #2.5) is untouched. Proof-of-
Restraint conformance and the demo were re-run: see the completion record. **No open bypass remains on a served surface.**

## Verification
```
$ python -m pytest tests/ -q          (full aiosh-mcp suite)
137 failed, 2002 passed, 6 skipped, 5 warnings in 377.80s
failures=137 missing-Rust-binary=136 known-baseline=1 other=0
$ python -m pytest tests/ -q -k "model_backend or mcp_server_core"   ->  392 passed
$ python -m pytest tests/test_capability_redeem_security.py -q        ->  25 passed (10 fail on pre-fix code)
$ python tools/test_por_conformance_suites.py   ->  CONFORMANT: C1..C6 PASS
$ python tools/demo_por.py                      ->  PROVABLY_RESTRAINED; post-anchor tamper REJECTED
```
