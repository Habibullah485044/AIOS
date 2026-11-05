# T-03336 Evidence: Agent Loop Hardening — observability Implementation

- Date: 2026-11-05
- **Real durations (LOOPOBS-INV3):** `advance_turn` measures `time.perf_counter()` from entry to recording. It is stored on the step and in its row
  (`duration_ms`). The fabricated 5.0/15.0 ms constants (T-03333 F1) are gone.
- `aiosh_mcp/agent_loop_observability.py`:
  - `ring_metrics(db, window)`: read-only (`mode=ro`), bounded window 1..100000. It gives event counts, ok/refused/irreversible step counts,
    p50/p95/max measured duration, refusals grouped into 7 reasons, irreversible use per **hashed** grant, and degraded-config rows.
    It filters with `substr()` rather than `LIKE`, because `_` is a LIKE wildcard.
  - `classify_refusal`, `health` (ok/degraded/failing) and `log_event`
- `AgentLoopService.stats()`: active/terminated/capacity plus counters (steps ok/refused, audit failures, gate unavailable, budget refusals).
- Logging: `aiosh_mcp.agent_loop` emits INFO for start/step/abort/complete and WARNING for audit_failure/gate_unavailable/timeout/budget_race.
  Lines are masked and carry structured `extra={"agent_loop": {...}}` with event, loop, run, outcome and reason code only. The logger has no handlers.

## Test-first
`tests/test_agent_loop_observability_impl.py` (17) against the scaffold code: **17 failed**. After the implementation:
```
17 passed in 1.16s
431 passed, 1 skipped, 908 deselected, 1 warning in 80.81s (0:01:20)   (battery)
```
Covered: durations measured and equal in snapshot and row; event counts; LOOPOBS-INV2 (`ok + refused == step`); refusal classification (9 cases);
the grant id never appears in metrics (hashed, 12 hex chars; LOOPOBS-INV1); window bounds and a missing DB; live counters; health states;
log lines are structured, ordered, and contain no grant id, args or secret; an audit failure is counted, logged at WARNING, and reports health `failing`.
