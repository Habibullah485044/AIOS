# T-03353 Research: Agent Loop Hardening — recovery & validation

- Date: 2026-11-05
- Scope: research only. **No code changed.**

## Facts (verified)
| # | Fact | Source |
|---|---|---|
| F1 | Loop state is in-memory only. When the process dies mid-loop (crash, kill, host restart), the ring keeps `start` + `step` rows **with no terminal row**: an *orphaned run*. | Reproduced: start + step, process dropped; history shows `['start','step']` |
| F2 | After a restart the orphan is invisible to the service (`get_snapshot` gives `LOOPSERV_ERR_NOT_FOUND`), and its id can never be reused (`start` gives `LOOPSERV_ERR_ALREADY_EXISTS`, single-use ids from #420). Nothing ever records that the run ended. | Reproduced |
| F3 | Metrics (T-03336) count events but have no notion of open vs. ended runs, so orphans are invisible in `health`. | `agent_loop_observability.ring_metrics` |
| F4 | Every loop row carries `loop_id` and `run_id` (#420), steps carry `step_index`, terminal events are `abort`/`complete`/`timeout`, and breaker terminations show no event row (FAILED is only in memory). A per-run ring validation is therefore possible from the ring alone. | T-03279..T-03346 |
| F5 | **Breaker terminations write no terminal row.** A loop FAILED by the iteration ceiling or the token budget looks exactly like an orphan in the ring. That is an audit gap: the ring cannot tell "ended by breaker" from "process died". | `agent_loop_service` (record_step sets FAILED; no audit call) |
| F6 | Precedent: `model_backend_adapters_recovery.py` gives read-only `validate_*` (a report), a token-gated `recover_*` (mutating, with backup/quarantine), and MCP tools for both. | file |

## Upstream references
- Write-ahead logging / crash recovery (an append-only log is replayed to reconstruct and close open work): SQLite WAL https://sqlite.org/wal.html
- "Fail-open must write an honest audit row" (ADR-0035 §F-2): recovery must *record* what happened. It must never fabricate a clean ending.

## Assumptions
- A1: Orphans should be **closed honestly** (a terminal row saying the run was abandoned and recovered). They must not be resumed: the in-memory
  budgets and grant binding cannot be reconstructed safely.
- A2: Recovery mutates the ring, so it must be PoR-gated like any state change (I-2).

## Decisions needed (for T-03354)
- D1: `validate_ring(db)` (read-only): a per-run report. It flags: orphaned (no terminal row and older than a grace period), rows after a terminal,
  a duplicate start, non-contiguous `step_index`, mixed `run_id` within one loop_id, and ok irreversible steps above the grant budget. It also checks that the chain verifies. (Recommended.)
- D2: `recover_orphans(db, grant, older_than_s)` (mutating, **grant-gated**): for each orphaned run it appends one `aios.agent_loop.recovered` row
  (outcome `abandoned`, the run's `run_id`, its last step index). It is idempotent, so a second run writes nothing. It never touches live loops held by the calling service. (Recommended.)
- D3: Fix F5: breaker terminations write an `aios.agent_loop.failed` terminal row with `LOOPSERV_ERR_CIRCUIT_BREAKER`, so they are not misread as orphans. (Recommended.)
- D4: Surfaces: MCP `aios_agent_loop_validate` (read-only), `aios_agent_loop_recover` (mutating, token), and CLI `validate-ring` / `recover`. Metrics add `orphaned_runs`, and health becomes `degraded` when it is above 0. (Recommended.)
