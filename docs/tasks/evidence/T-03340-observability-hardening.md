# T-03340 Evidence: Agent Loop Hardening — observability Hardening

- Date: 2026-11-05

## Changes
| Gap | Fix |
|---|---|
| A metrics query had no wall-clock bound of its own. When the MCP call timed out (15 s), `abandon_on_cancel` left the worker thread **still scanning**. | `ring_metrics(..., deadline_s=10)` installs a SQLite **progress handler** that interrupts the query inside SQLite once the budget passes. It raises `ObservabilityReadError` ("exceeded its budget; use a smaller window"), which the MCP tool reports as `ring.error` and health `failing`, and the CLI as exit 1. So abandoned threads stop too. |
| Rows were materialised into a list (100k tuples) before aggregating. | The cursor is **streamed** newest to oldest. Aggregates are order-independent; first/last ids and timestamps are tracked as it goes. Memory is constant apart from the duration samples. |
| A broken logging handler (a host misconfiguration) could raise out of `log_event` into a loop step. | `log_event` contains any logging exception: observability can never break execution or the audit path. |

## Tests (`tests/test_agent_loop_observability_hardening.py`)
```
3 passed in 3.16s
```
| Test | Old code | New code |
|---|---|---|
| deadline aborts inside SQLite (20k rows, budget 0) | **fails** (no deadline) | `ObservabilityReadError` with the budget message |
| streamed results exact (20k rows: counts, ids, refusal mix, max duration, newest-10 window) | passes | passes (unchanged semantics) |
| exploding log handler during start/step/complete | **fails** (RuntimeError reaches the step) | the step is ok and the loop completes |

## Cleanup
Every connection is closed in `finally`; the progress handler dies with the connection. No temp files, no child processes.
