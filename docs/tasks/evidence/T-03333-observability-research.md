# T-03333 Research: Agent Loop Hardening — observability

- Date: 2026-11-05
- Scope: research only. **No code changed.**

## Facts (verified)
| # | Fact | Source |
|---|---|---|
| F1 | Every step's `duration_ms` is a **hard-coded constant**: `5.0` for refused and `15.0` for ok. Any latency telemetry built on step records today would be fabricated. | `agent_loop_service.py` (`duration_ms=5.0` / `15.0`) |
| F2 | No agent-loop module logs anything (`logging` is not imported). Failures such as audit-write errors, gate unavailability and degraded config surface only as return values or audit rows. | grep `aiosh_mcp/agent_loop_*.py` |
| F3 | The durable, cross-process record is the hash-chained `audit_ring`. Rows exist for start, step (with outcome, `classify_overall_verdict`, `irreversible`, `grant_token`), abort, complete, timeout, init and config. The refusal reason is in `outcome_detail`. Aggregates (counts by outcome, refusal reason, irreversible use) can be derived from it **without new storage**. | T-03279..T-03330 |
| F4 | In-process state not in the ring: the number of active loops and capacity use (`AgentLoopService._loops`, `_capacity`). | `agent_loop_service.py` |
| F5 | Precedent: `model_backend_adapters_observability.py` keeps in-memory counters and a health status behind an MCP tool, and uses `logging.getLogger(__name__)`. `mcp_server_core_observability.py` registers read-only MCP tools. Neither uses an external metrics library. | files |
| F6 | No `opentelemetry`, `prometheus_client` or `statsd` is installed or used anywhere in the package. | `python -c "import opentelemetry"` -> ModuleNotFoundError; grep |
| F7 | Existing read surfaces to reuse: `read_loop_history` (read-only `mode=ro`), the MCP `_run` timeout wrapper, and the CLI's `--json` envelope. | T-03296..T-03300 |

## Upstream references
- Python `logging` (library code should use module loggers and add no handlers): https://docs.python.org/3/howto/logging.html#configuring-logging-for-a-library
- `time.perf_counter` (monotonic, for durations): https://docs.python.org/3/library/time.html#time.perf_counter
- OpenTelemetry semantic conventions, used **as naming guidance only** (no dependency): https://opentelemetry.io/docs/specs/semconv/
- Google SRE "four golden signals" (latency, traffic, errors, saturation): https://sre.google/sre-book/monitoring-distributed-systems/

## Assumptions
- A1: Operators want answers to "what did loops do, how often were they refused and why, how much irreversible budget is used, is the subsystem healthy?"
  more than live tracing.
- A2: An aggregate query over at most a bounded window of the ring (e.g. the last 10k rows) is fast enough for an on-demand tool.

## Decisions needed (for T-03334)
- D1: **Measure real durations**: `time.perf_counter` from turn entry to the step being recorded. This replaces the constants (F1). (Recommended.)
- D2: **Ring-derived metrics** (`agent_loop_metrics(db_path, window)`): counts per event/outcome, refusals grouped by reason code, irreversible use per grant,
  terminal states, plus p50/p95 step duration from the measured `duration_ms` recorded on step rows. Read-only, bounded window. (Recommended.)
- D3: **Live gauges** from the service: active loops, capacity, and counters of audit failures, gate unavailability and budget refusals since start. (Recommended.)
- D4: **Structured logging**: the module logger `aiosh_mcp.agent_loop` emits one masked event per consequential action at INFO and per failure at WARNING.
  It adds no handlers (the library rule). (Recommended.)
- D5: Exposure: MCP `aios_agent_loop_metrics` (read-only) and CLI `metrics [--window N] [--json]`. Health is `ok`, `degraded` (config degraded or any audit/gate
  failure in the window) or `failing`. (Recommended.)
- D6: No new dependency (F6).
