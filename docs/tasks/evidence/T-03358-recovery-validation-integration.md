# T-03358 Evidence: Agent Loop Hardening — recovery & validation Integration

- Date: 2026-11-05

## Production surfaces
| Surface | Change |
|---|---|
| MCP | `aios_agent_loop_validate(grace_s)` (read-only; on the metrics limiter) and `aios_agent_loop_recover(capability_token, grace_s)` (mutating, grant-gated). Both pass this server's `live_run_ids()`, so live loops are never reported or closed. Catalog +2; `TOOL_ANNOTATIONS` covers 12. |
| CLI | `validate-ring [--grace S] [--json]` (exit 0 when ok, 1 when there are problems or orphans) and `recover (--token-env VAR \| --token-stdin) [--grace S] [--json]`. The token is never accepted on argv. |
| Service | `AgentLoopService.live_run_ids()` |
| Metrics | MCP and CLI metrics report `orphaned_runs` (default grace 900 s). Health is `degraded` while any exist; the two stay in parity. |
| Spec | New §5d (keeps the CI drift test green; expanded in T-03361). |

## Integration smoke (real stdio server)
`tests/test_agent_loop_recovery_integration.py`:
- "Another process" crashes mid-loop. Over MCP, `validate` (grace 0) reports exactly that orphan. Metrics (grace 900) report 0 orphans, because a fresh crash counts as open, and health is `ok`.
- A forged recover token gets `LOOPSERV_ERR_UNAUTHORIZED`. A real grant recovers the run; validate is then ok and health `ok`. CLI `validate-ring` exits 0.
- A second crash makes CLI `validate-ring` exit 1; CLI `recover --token-env` closes it.
- In-process with grace 0, an orphan degrades health.
```
2 passed in 4.99s
```
Note: the first draft expected metrics to flag the seconds-old crash. That contradicts the spec's grace period, so the test was corrected, not the code.
