# T-03356 Evidence: Agent Loop Hardening — recovery & validation Implementation

- Date: 2026-11-05
- `aiosh_mcp/agent_loop_recovery.py`:
  - `validate_ring`: read-only, never creates the DB. Runs are grouped by `run_id` from trusted-actor rows. It reports orphans (open, older than the grace period, not live),
    `missing_start`, `duplicate_start`, `step_index_gap`, `rows_after_terminal`, `run_id_mixed`, `budget_exceeded` (per grant against `max_irreversible`), plus `chain_ok` (`verify_live`).
    Listings are capped at 1000.
  - `recover_orphans`: **PoR I-2**. It redeems a single-use grant scoped to `aios.agent_loop.recover`. For each orphan it re-checks under `BEGIN IMMEDIATE` that the run is
    still open, then writes one `aios.agent_loop.recovered` row (outcome `abandoned`). It is idempotent and never touches live runs.
- **Breaker terminal row (T-03353 F5):** a breaker FAIL now writes `aios.agent_loop.failed` right after its step row, so the ring tells "ended by breaker" from "process died".
- New code `LOOPREC_ERR_READ`, with its `ERROR_MEANINGS` entry and spec §6 entry (the two-way doc and drift tests require both).
- The fuzz reference model now predicts the `failed` row when a step trips the iteration ceiling. The fuzzer passes, i.e. the new row appears exactly when the spec says.

## Test-first
`tests/test_agent_loop_recovery_impl.py` (7) on the scaffold code: **7 failed**. After:
```
7 passed in 1.35s
battery: 493 passed, 1 skipped, 908 deselected, 1 warning in 95.07s (0:01:35)
```
Covered:
- a clean ring validates
- a crashed run is "open" within the grace period and orphaned after it; it is recovered exactly once, its history ends `recovered`, and the ring then validates
- recovery refuses an empty, forged or out-of-scope grant and writes nothing
- live runs are skipped
- a breaker writes `failed` and is not mistaken for an orphan
- a deleted step row is reported as `step_index_gap`, and the chain fails verification
- validation never creates the DB
