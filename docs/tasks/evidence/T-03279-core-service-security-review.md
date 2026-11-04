# T-03279 Security Review: Agent Loop Hardening Core Service — Abuse Scenarios

- Date: 2026-11-05
- Scope: `aiosh_mcp/agent_loop_service.py`, its MCP tools (T-03278), and the data-model tool
  `aios_agent_loop_init` (T-03268), which share the same capability check.

## Findings (all were open on `main` before this task — now fixed)

| # | Severity | Finding | Fix |
|---|---|---|---|
| F1 | **Critical** | PoR I-2 bypass: `start_loop`/`advance_turn`/`abort_loop` and `aios_agent_loop_init` accepted **any non-empty string** as a capability token. Nothing was redeemed. | New `aiosh_mcp/agent_loop_gate.py` `PepCapabilityGate.redeem` calls `audit_client.grant_redeem` (single-use, expiry, revocation, `scope.tools` must cover `aios.agent_loop.start`). |
| F2 | **High** | Loop hijack: any token could advance/abort any loop. | Loop is bound to the redeemed grant id; advance/abort require the same id (`hmac.compare_digest`). |
| F3 | **High** | Policy self-approval: `policy_allowed` came from the caller, so the PEP gate (LOOPSERV-INV3) was advisory. | Caller verdict can only *narrow*: every tool call is re-checked against the bound grant's `scope.tools`, expiry and revocation before `EXECUTE_TOOL`. |
| F4 | Medium | No audit rows (spec LOOPSERV-INV2). | `aios.agent_loop.{start,step,abort,timeout}` rows written to the hash-chained `audit_ring`, args masked via `mask_secrets`. |
| F5 | Low | Watchdog crashed (illegal OBSERVE->FAILED). | Fixed in T-03277 (terminates via ABORTED). |

## Abuse scenarios (each is a test in `tests/test_agent_loop_core_service_security.py`)
| ID | Scenario | Expected | Result |
|---|---|---|---|
| S1 | Forged token "anything" | UNAUTHORIZED, nothing registered | PASS |
| S2 | Replay a redeemed single-use grant for a 2nd loop | UNAUTHORIZED "already redeemed" | PASS |
| S3 | Grant scoped only to `aios.fs.read` starts a loop | UNAUTHORIZED | PASS |
| S4 | Expired grant / revoked grant | UNAUTHORIZED | PASS |
| S5 | Grant B drives or aborts loop A | UNAUTHORIZED, loop A untouched | PASS |
| S6 | `policy_allowed=True` for `fs.write` outside scope | step `refused`, "not in grant scope" | PASS |
| S7 | Grant revoked mid-loop | later tool calls `refused` | PASS |
| S8 | Audit coverage + secret in tool args | 5 rows (redeem/start/step/refused/abort), no secret, chain verifies | PASS |
| S9 | Bad config with a valid grant | rejected before redemption, grant still usable | PASS |

## Input validation / injection
- `loop_id` is constrained by `LOOP_ID_PATTERN` (`^[a-zA-Z0-9_\-]{8,64}$`); shell metacharacters rejected (T-03277 test).
- No paths, subprocesses or SQL string building in the service; grant DB access uses parameterised queries in `audit_client`.
- Tool args are stored as a masked, length-capped summary (`MAX_ARGS_SUMMARY_BYTES`); the loop never executes tools itself.

## PoR standing-rule check (I-2)
Every state-changing path — `start_loop`, `advance_turn`, `abort_loop`, MCP `aios_agent_loop_{start,advance,abort}`,
and `aios_agent_loop_init` — now requires a redeemed grant (start/init) or the bound grant (advance/abort).
Read-only `get_snapshot` / `aios_agent_loop_snapshot` / `aios_agent_loop_status` need none. **No known bypass remains open.**

## Residual risks (carried to T-03280 hardening)
- Audit-write failure after a state change currently raises after the in-memory transition; needs an honest fail path.
- Registry is unbounded (`MAX_REGISTRY_CAPACITY` exists in the data model but is not applied to the service).
- `timeout_ms_per_step` is not enforced (the service does not run tools, so there is nothing to time yet).

## Verification
```
cd code/aiosh-mcp && python -m pytest tests/ -k agent_loop -q
74 passed, 909 deselected in 4.88s
```
Full suite (release tests excluded — see note): 822 passed, 137 failed; 136 failures are
`FileNotFoundError: [WinError 2]` (Rust binary not built), 1 is the binary-exists assertion, and
`test_runbook_config_integration::test_integration_dynamic_session_capping_via_env` is an
order-dependent flake (passes alone, on this branch and on `main`).

Note: release tests were excluded because `test_release_*smoke` writes `aios_backup_*.zip` into the
working directory; one run produced a 6.3 GB archive and filled the disk.
