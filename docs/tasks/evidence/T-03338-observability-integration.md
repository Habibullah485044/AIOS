# T-03338 Evidence: Agent Loop Hardening — observability Integration

- Date: 2026-11-05

## Production surfaces
| Surface | Change |
|---|---|
| MCP | New **`aios_agent_loop_metrics(window=10000)`** (`readOnlyHint`; schema `window` 1..100000). It returns `{ring, live, health}`, uses the shared `_run` timeout wrapper, and turns an unreadable ring into `ring.error` with health `failing`. Catalog: 63 -> **64** tools. `TOOL_ANNOTATIONS` now covers 9 tools; the scaffold test was updated. |
| CLI | New **`python -m aiosh_mcp.agent_loop_cli metrics [--window N] [--json]`**: ring metrics plus health. A bad window exits 2; a corrupt DB exits 1 (`LOOPOBS_ERR_READ`). The human view shows health, window, events, steps with p50/p95/max duration, and refusal reasons. |
| Logging | The service's `aiosh_mcp.agent_loop` logger (T-03336) is active in the server process; it has no handlers, so the host decides where logs go. |

## Integration smoke (real stdio server)
`tests/test_agent_loop_observability_integration.py`: a loop runs **through** `python -m aiosh_mcp.server` (start, ok read, refused write, complete), then:
- `aios_agent_loop_metrics` reports health ok, steps ok=1/refused=1, refusals.constitution=1, and live counters 1/1. The grant id is absent from the output.
- A schema-invalid `window=0` is an MCP tool error.
- **Parity:** CLI `metrics --json` on the same `audit.db` returns an identical `ring` object.
```
1 passed in 5.14s
403 passed, 1 skipped, 950 deselected, 1 warning in 83.12s (0:01:23)   (all agent-loop suites)
```
