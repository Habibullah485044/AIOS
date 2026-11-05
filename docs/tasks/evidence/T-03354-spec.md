# T-03354 Specification: Agent Loop Hardening — recovery & validation

- Date: 2026-11-05
- Adopts T-03353 D1..D4. Everything is **AIOS-specific**. New module `aiosh_mcp/agent_loop_recovery.py`, stdlib only.

## 1. Run model (derived from the ring)
A **run** is the set of agent-loop rows written by the gate's actor that share a `run_id`. Terminal events are
`abort`, `complete`, `timeout`, `failed` (new, §4) and `recovered` (new, §3). A run is **open** if it has no terminal row.
It is **orphaned** if it is open, its newest row is older than `grace_s` (default 900 s), and it is not held live by the calling service.

## 2. `validate_ring(db_path=None, grace_s=900, live_runs=()) -> dict` (read-only)
```
{"runs": n, "open": n, "orphaned": [{"loop_id","run_id","last_step_index","last_ts"}],
 "problems": [{"loop_id","run_id","kind","detail"}], "chain_ok": bool, "ok": bool}
```
Problem kinds:
- `rows_after_terminal`
- `duplicate_start`
- `step_index_gap` (indices must be 0..n-1, contiguous)
- `run_id_mixed` (one loop_id carrying more than one run_id)
- `budget_exceeded` (ok irreversible steps above the grant's `max_irreversible`, when the grant still exists)
- `missing_start`

`ok` means no problems, no orphans, and `chain_ok`. The result is bounded: at most 1000 runs are listed, and `truncated: true` is set past that. It opens the DB read-only (`mode=ro`).

## 3. `recover_orphans(db_path, capability_token, grace_s=900, live_runs=()) -> dict` (mutating)
- **PoR I-2.** The token is redeemed as a PEP grant whose `scope.tools` covers `aios.agent_loop.recover` (single-use). An empty, forged or out-of-scope token is
  `LOOPSERV_ERR_UNAUTHORIZED`, and nothing is written.
- For each orphaned run, append exactly one `aios.agent_loop.recovered` row: outcome `abandoned`, args `{loop_id, run_id, last_step_index, last_ts}`,
  `grant_token` = the recovery grant. Each check-and-write runs under `BEGIN IMMEDIATE` (it re-checks that the run is still open), so concurrent recoveries cannot double-close a run.
- Returns `{"recovered": [...], "skipped_live": n}`. It is idempotent: a second call finds nothing.
- Recovery never *resumes* a run (grant binding and budgets are not reconstructable). It records the end honestly.

## 4. Breaker terminal row (closes T-03353 F5)
When a breaker FAILs a loop during `advance_turn`, the service writes `aios.agent_loop.failed` (outcome `failed`, detail = the
`LOOPSERV_ERR_CIRCUIT_BREAKER: ...` reason) right after the step row. So the ring distinguishes "ended by breaker" from "process died".

## 5. Surfaces
- MCP `aios_agent_loop_validate(grace_s=900)` (read-only) and `aios_agent_loop_recover(capability_token, grace_s=900)` (destructive=false, mutating;
  `live_runs` = this server's runs).
- CLI `validate-ring [--grace S] [--json]` (exit 0 when ok, 1 when problems or orphans) and
  `recover --token-env VAR | --token-stdin [--grace S] [--json]`.
- Metrics gain `orphaned_runs`, and health is `degraded` when it is above 0.

## 6. Invariants
- LOOPREC-INV1: every run in the ring ends with exactly one terminal row once recovery has run.
- LOOPREC-INV2: recovery writes only `recovered` rows, only for orphaned runs, and only after grant redemption.
- LOOPREC-INV3: validation is read-only and never creates the DB.
