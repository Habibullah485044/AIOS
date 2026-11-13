# T-03433 Research: Tool Registry & Taxonomy — observability

- Date: 2026-11-13
- Scope: research only. **No code changed.**
- Previous epic: security policy (T-03423..T-03432; [verify](T-03432-verify.md))

## Facts (verified)
| # | Fact | Source |
|---|---|---|
| F1 | `aios_tool_registry_stats` already reports:<br>• per-process service counters: `mode`, `decisions`, `unregistered`, `disagreements` by kind (`unregistered`, `grant`, `irreversible`, `scope`), `unregistered_samples` (keyed hashes, never names, capped by config `unregistered_samples`=50), `catalog_entries`;<br>• `reports.lines` / `reports.suppressed`;<br>• `policy_revision`;<br>• the resolved config and its sources, and `config_errors` (codes only). | Live call on this host; `tool_registry_api.py`, `tool_registry_service.ToolRegistryService.stats` |
| F2 | The counters are **not split by surface**. Dispatch and the agent loop share one service singleton, so a decision from either surface lands in the same totals. Only the stderr report line carries `surface`. | `tool_registry_service.py` (`decide`, `report(…, surface)`) |
| F3 | Disagreements reach stderr as one JSON line (`event: "tool_registry.disagreement"`) per distinct (surface, tool, kinds), capped at `MAX_REPORT_LINES` = 32 per process (config `report_max_lines`). Past the cap they are only counted. | `tool_registry_service.report` |
| F4 | A policy failure (the catalog or service raising) is announced **once per surface per process** on stderr, and is not counted. After the first line, an operator cannot tell one failure from a thousand. | `tool_registry_policy._announce_failure` (`_LOGGED`) |
| F5 | **Nothing counts strict-mode enforcement:** neither how many grant refusals the registry caused (`registry_added_grant`) nor how many agent-loop steps it marked irreversible. They can be recovered from the durable ring, because the refusal row's `outcome_detail` ends with `(tool registry strict, catalog trp-…)` or `(tool registry unavailable, strict: fail closed)`. | T-03426 / T-03430 (honest-row test); `_dispatch.py` refusal rows (`outcome: "refused"`, `outcome_detail: reason`) |
| F6 | **Capability-token refusals leave no record.** `capability_redeem.redeem_capability` writes a `pep.capability.redeem` row only on success. A forged, expired, revoked, out-of-scope or malformed token returns an error envelope and writes nothing, not even a stderr line. Repeated forged-token attempts on the six gated tools (T-03429 F1) are invisible after the fact. | `capability_redeem.py`; `audit_client.grant_redeem` (returns before `write_audit_row` on `grant_check` failure) |
| F7 | No registry module and not `capability_redeem` imports `logging`. Every output is a direct `sys.stderr` write through `tool_registry_service._stderr_line`, which never writes to stdout, the MCP JSON-RPC channel. | grep `import logging\|getLogger` over `tool_registry_*.py`, `capability_redeem.py` (no matches) |
| F8 | There is no latency measurement for `decide()` / `evaluate()`. The only timing bound is `test_repeated_calls_are_cheap`-style tests. | grep `perf_counter` (no matches in registry modules) |
| F9 | The precedent is five `*_observability.py` modules (agent loop, compliance, incident runbooks, MCP core, model backends). They provide:<br>• ring-derived metrics read with `sqlite3 … ?mode=ro`, a bounded `window` (default 10 000, max 100 000) and a query deadline (10 s);<br>• live gauges, and a `health` of `ok` / `degraded` / `failing`;<br>• masked structured log events through a module logger that adds no handlers;<br>• a read-only MCP tool, plus a CLI `metrics --json`;<br>• no external metrics dependency. | `agent_loop_observability.py` (`ring_metrics`, `health`, `log_event`, `DEFAULT_WINDOW`, `MAX_WINDOW`, `DEFAULT_QUERY_DEADLINE_S`); [T-03333 research](T-03333-observability-research.md) |
| F10 | `opentelemetry`, `prometheus_client` and `statsd` are not used anywhere in the package (T-03333 F6; unchanged). | grep |

## Upstream references
- Python logging for libraries (module loggers, no handlers; `NullHandler` guidance):
  https://docs.python.org/3/howto/logging.html#configuring-logging-for-a-library
- SQLite URI `mode=ro` (read-only open, so the metrics reader cannot write the ring): https://www.sqlite.org/uri.html
- `time.perf_counter` (monotonic, for durations): https://docs.python.org/3/library/time.html#time.perf_counter
- OpenTelemetry semantic conventions, **as naming guidance only**: https://opentelemetry.io/docs/specs/semconv/
- Google SRE, the four golden signals (traffic, errors, latency, saturation):
  https://sre.google/sre-book/monitoring-distributed-systems/
- OWASP Logging Cheat Sheet (log authorization failures; never log secrets or tokens):
  https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html

## Assumptions
- A1: Operators most want answers to:
  - Is the registry healthy?
  - In strict mode, how many calls did it refuse, and which tools?
  - Are capability tokens being forged or replayed?
  - Did the catalog change, and when?

  They want those more than per-call tracing.
- A2: A bounded window over the ring (≤ 100 000 rows) is fast enough on demand, as for the agent loop (T-03333 A2).
- A3: Logging every *refused* capability attempt is wanted (OWASP: authorization failures), provided the token is never
  logged in clear.

## Unknowns
- U1: Should a refused capability attempt write a **durable audit row** (ADR-0035 F-2-style honesty) or only an
  in-process counter plus a log line? A row is durable and cross-process, but lets an unauthenticated caller grow the
  ring, so it needs a rate or size bound.
- U2: Should the counters be split by surface (F2) by changing the service singleton, or derived in the policy layer,
  which already knows the surface?
- U3: Should there be a CLI `metrics` subcommand? The registry CLI is deliberately DB-free (§6c: "no DB, no audit
  rows"), so ring metrics there would break a documented property.

## Decisions needed (for T-03434)
- D1: **Policy-layer counters** in `tool_registry_policy`, per surface:
  - evaluations;
  - registry-added grants, and registry-added irreversible marks;
  - failures by exception type (fixes F4: counted, still announced once).

  Lock-protected and reset by `reset_process_state()`. (Recommended.)
- D2: **Capability-gate counters and log:**
  - `capability_redeem` counts redeemed and refused, the refusals grouped into a closed set of reason classes
    (`missing`, `malformed`, `unknown_or_revoked`, `expired`, `scope`, `already_redeemed`, `unavailable`, `other`);
  - one masked WARNING per refusal through a module logger (`aiosh_mcp.capability`) that adds no handlers;
  - the token is shown only as a short keyed hash, never in clear.

  Answers U1 with *counter + log*, **no new audit rows**, to keep ADR-0035 F-2 and the "no new rows" rule of T-03424.
  (Recommended.)
- D3: **Ring-derived metrics** (`tool_registry_ring_metrics(db_path, window)`), read-only (`mode=ro`), bounded window,
  deadline:
  - registry-attributed refusals by tool and by suffix kind (strict / unavailable);
  - `pep.capability.redeem` successes by tool.

  (Recommended.)
- D4: **Health:**
  - `failing` if the catalog cannot be built, or any strict-mode policy failure occurred;
  - `degraded` if there are config errors, shadow-mode failures, or the report cap was hit;
  - otherwise `ok`.

  (Recommended.)
- D5: **Exposure:** extend `aios_tool_registry_stats` with `policy`, `capability` and `health` blocks, and add a
  read-only `aios_tool_registry_metrics(window)` for the ring part. Answer U3: **no** CLI ring metrics, to keep the
  CLI DB-free. (Recommended.)
- D6: No new dependency (F10). No decision latency histogram yet (F8): the decision is in-memory and sub-millisecond,
  so record it as a limitation rather than add a hot-path clock. (Recommended.)
