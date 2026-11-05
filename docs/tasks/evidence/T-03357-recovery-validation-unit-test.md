# T-03357 Evidence: Agent Loop Hardening — recovery & validation Unit Test

- Date: 2026-11-05
- Test file: `code/aiosh-mcp/tests/test_agent_loop_recovery_unit.py` (12 cases, hand-built rings)

| Area | Cases |
|---|---|
| Problem kinds (one ring each) | `rows_after_terminal`, `duplicate_start`, `step_index_gap`, `run_id_mixed`, `missing_start`; `budget_exceeded` against a grant's `max_irreversible` (the grant id is hashed in the report) |
| Boundaries | grace period (open vs. orphaned); rows from an untrusted actor are ignored entirely; legacy rows without `run_id` are skipped; listing cap gives `truncated` |
| Failure modes | **two concurrent recoveries** close each of 4 orphans exactly once (4 `recovered` rows total) and the ring then validates; a replayed single-use recovery grant is refused; a corrupt DB raises `LOOPREC_ERR_READ` |

## Fails when broken
Mutation: the under-lock re-check in `recover_orphans` was disabled (`if False and closed`). `test_concurrent_recoveries_close_each_run_once` **failed in 3/3 runs**:
both recoveries closed the same runs. Restored:
```
12 passed in 1.54s
```
Note: the first run had 1 failure from a test-helper bug (untrusted actor applied only to the start row). The helper was fixed; the code was unchanged.
