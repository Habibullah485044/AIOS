# T-03286 Evidence: Agent Loop Hardening — CLI surface Implementation

- Date: 2026-11-05
- Implemented `code/aiosh-mcp/aiosh_mcp/agent_loop_cli.py` per T-03284: `validate`, `run` and `history`,
  `--json`, exit codes 0..4, NUL-byte rejection, and plan validation before redemption (LOOPCLI-INV3).
- Implemented `AgentLoopService.complete_loop` (OBSERVE -> COMPLETED). It is token-bound and writes an audit row
  `aios.agent_loop.complete`.
- Reused helpers rather than duplicating them: the `AgentLoopService` methods, `PepCapabilityGate` (grant redemption and audit),
  `TOOL_NAME_PATTERN` and the per-turn caps from the service, and `mask_secrets`. `history` uses a **read-only** SQLite
  URI (`mode=ro`) with `json_extract`. No new dependencies (stdlib `argparse`, `json`, `sqlite3` only).

## Test-first
`tests/test_agent_loop_cli_impl.py` was written first and failed (`5 failed`, all stubs raising `NotImplementedError`).
After the implementation:
```
5 passed in 0.83s
94 passed, 909 deselected in 6.06s   (all agent-loop suites, no regression)
```
The scaffold's stub-must-raise checks were removed from `test_agent_loop_cli_scaffold.py` because they no longer apply.

## Audit invariant
One `run` of a 2-turn plan writes exactly: `pep.capability.redeem`, `aios.agent_loop.start`, 2 x `aios.agent_loop.step`,
and `aios.agent_loop.complete` (asserted in `test_run_executes_plan_and_completes`).

## Real invocation (`python -m`, isolated AIOSH_HOME, grant scoped to start + aios.fs.read)
```
plan OK: 2 turn(s)
exit=0
[0] ok      aios.fs.read
[1] refused fs.write  LOOPSERV_ERR_POLICY_REFUSED: Policy evaluation refused tool invocation: tool 'fs.write' not in grant scope.tools
loop loop-cli-demo-01: COMPLETED (2 turn(s), 1 refused, 0 skipped)
exit=0
error [LOOPSERV_ERR_UNAUTHORIZED] (exit 3): LOOPSERV_ERR_UNAUTHORIZED: grant gr_cli_demo already redeemed at 2026-11-04T20:34:24.792991Z
exit=3
     2 2026-11-04T20:34:24.812387Z aios.agent_loop.start    ok
     3 2026-11-04T20:34:24.830849Z aios.agent_loop.step     ok
     4 2026-11-04T20:34:24.849524Z aios.agent_loop.step     refused
     5 2026-11-04T20:34:24.862693Z aios.agent_loop.complete ok
4 event(s) for loop-cli-demo-01
exit=0
```
