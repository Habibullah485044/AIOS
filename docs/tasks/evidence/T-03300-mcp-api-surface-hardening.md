# T-03300 Evidence: Agent Loop Hardening — MCP/API surface Hardening

- Date: 2026-11-05
- Files: `aiosh_mcp/agent_loop_mcp.py`, `aiosh_mcp/agent_loop_gate.py` (`read_loop_history(..., after_id)`),
  `tests/test_agent_loop_mcp_hardening.py` (4 cases)

## Gaps found and fixed
| Gap | Evidence | Fix |
|---|---|---|
| **Event-loop stall.** FastMCP calls *sync* tools directly on the event-loop thread (`FuncMetadata.call_fn_with_arg_validation`: `return fn(**args)`). One call waiting on a locked audit DB (busy_timeout 5 s) froze every other request on the stdio server. | SDK source, mcp 1.29.1 | All 7 tools are now `async`. Blocking work runs in `anyio.to_thread.run_sync(..., abandon_on_cancel=True)`. `test_blocking_call_does_not_stall_other_requests` shows a `list` call finishing while a 1 s write is in flight. |
| **No wall-clock bound** per call | — | `anyio.fail_after(TOOL_CALL_TIMEOUT_S=15)` returns an explicit `LOOPMCP_ERR_TIMEOUT` envelope. For mutating tools it says "outcome unknown: check snapshot/history before retrying", so it never claims success or failure it cannot know. |
| **Unbounded responses.** History could return 1000 rows x 64 KiB args (about 64 MB); a snapshot could carry 1000 steps. | arithmetic on the caps | History is paginated by an `after_id` cursor with a 1 MiB budget (whole events, `truncated` + `next_after_id`). Snapshot has `steps_tail` (default 100, 0..1000) plus `steps_total`. |

## Error envelope / no silent failure
Every exception path in `_run` maps to a `LoopResultEnvelope` with an `error_code`: service errors, `HistoryReadError`
-> `LOOPMCP_ERR_AUDIT_READ`, timeout -> `LOOPMCP_ERR_TIMEOUT`, anything else -> `LOOPSERV_ERR_INTERNAL`. Schema violations
remain MCP tool errors (T-03294).

## Resource cleanup
The history reader closes its read-only connection in `finally`. Gate connections use `closing()` (leak test in T-03280).
A timed-out worker thread is abandoned, not killed. It finishes under the service's `RLock`, so state stays consistent,
and its audit row is still written, which is why the envelope says "outcome unknown".

## Tests
```
4 passed in 3.90s
193 passed, 909 deselected in 23.38s   (all agent-loop suites incl. stdio wire tests)
```
Pagination test: 13 events over more than one page with a 2000-byte budget, ids strictly increasing, no gaps or duplicates.
