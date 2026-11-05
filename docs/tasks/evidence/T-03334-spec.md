# T-03334 Specification: Agent Loop Hardening — observability

- Date: 2026-11-05
- Adopts T-03333 D1..D6. Every name is **AIOS-specific**. Stdlib only (`logging`, `time`, `sqlite3`, `statistics`).

## 1. Real durations (D1)
`advance_turn` measures `time.perf_counter()` from entry to the moment the step is recorded, and stores it as `duration_ms` (float, ms, rounded to 0.001).
The same value goes into the step row args (`duration_ms`). The constants 5.0 and 15.0 are removed.

## 2. Ring-derived metrics (D2)
New `aiosh_mcp/agent_loop_observability.py`:
`ring_metrics(db_path=None, window=10_000) -> dict`, read-only (`mode=ro`), over the newest `window` `aios.agent_loop.*` rows (1..100_000).
```
{"window": {"rows": N, "first_id": a, "last_id": b, "first_ts": ..., "last_ts": ...},
 "events":   {"start": n, "step": n, "abort": n, "complete": n, "timeout": n, "init": n, "config": n},
 "steps":    {"ok": n, "refused": n, "irreversible_ok": n,
              "duration_ms": {"count": n, "p50": x, "p95": x, "max": x}},
 "refusals": {"constitution": n, "irreversible_budget": n, "scope": n, "caller": n, "target": n, "gate_unavailable": n, "other": n},
 "irreversible_by_grant": [{"grant_hash": "sha256[:12]", "ok": n}],     # grant ids are bearer tokens and are never emitted
 "degraded_config_rows": n}
```
Refusal reasons are classified from `outcome_detail` by prefix or code. A missing DB or table returns zero counts. Older rows without `duration_ms` are excluded from the percentiles.

## 3. Live gauges and counters (D3)
`AgentLoopService.stats() -> dict`:
`{"active_loops", "terminated_loops", "capacity", "counters": {"steps_ok", "steps_refused", "audit_failures", "gate_unavailable", "budget_refusals"}}`.
Counters are in-process, monotonic, since construction, and updated under the service lock.

## 4. Structured logging (D4)
Module logger `logging.getLogger("aiosh_mcp.agent_loop")`. It adds **no handlers**. Events:
- INFO for `start`, `step`, `abort`, `complete`
- WARNING for `audit_failure`, `gate_unavailable`, `timeout`, `budget_race`

Message format: `agent_loop <event> loop=<id> run=<run_id> outcome=<o> [reason=<code>]`. Structured fields are passed via `extra={"agent_loop": {...}}`.
**Never logged:** grant ids, tool args, the args digest. Everything goes through `mask_secrets`.

## 5. Exposure and health (D5)
- MCP `aios_agent_loop_metrics(window=10000)` (`readOnlyHint`). It returns `{"ring": ring_metrics(...), "live": service.stats(), "health": h}`.
- CLI `python -m aiosh_mcp.agent_loop_cli metrics [--window N] [--json]` returns the ring metrics plus health. There are no live gauges in a one-shot process.
- `health` is one of:
  - `failing`: any audit failure in the live counters, or the ring is unreadable
  - `degraded`: config is degraded, gate-unavailable is above 0, or `degraded_config_rows` is above 0 in the window
  - `ok`: otherwise

## 6. Errors and effects
Read-only. Writes nothing. A bad `window` is a schema error (MCP) or exit 2 (CLI). A corrupt DB gives `LOOPOBS_ERR_READ` (MCP envelope) or exit 1 (CLI).

## 7. Invariants
- LOOPOBS-INV1: no metric or log line contains a grant id, tool args or a secret.
- LOOPOBS-INV2: `steps.ok + steps.refused == events.step` within a window.
- LOOPOBS-INV3: every recorded `duration_ms` is measured, never a constant.
