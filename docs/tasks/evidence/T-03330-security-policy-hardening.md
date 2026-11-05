# T-03330 Evidence: Agent Loop Hardening — security policy Hardening

- Date: 2026-11-05
- Closes the T-03329 residual "budget check-then-write is not atomic across processes".

## Change
- `PepCapabilityGate.audit(..., budget_guard=N)` re-counts the grant's ok irreversible rows and inserts the new ok row **inside one
  `BEGIN IMMEDIATE` transaction**. If the budget is already spent it rolls back and raises `BudgetExhausted(used, budget)`, and nothing is written.
- The service writes a guarded ok row **before** the in-memory record. On `BudgetExhausted` it converts the step into a normal refused step
  (`LOOPPOL_ERR_IRREVERSIBLE_BUDGET: used N of M`, one refused row). `_audit_or_terminate` treats `BudgetExhausted` as a policy outcome,
  not an audit failure, so the loop is not aborted.
- The count SQL is shared by `irreversible_used` and the guard, so the two cannot drift. The test double mirrors the guard.

## Tests (`tests/test_agent_loop_policy_hardening.py`)
```
2 passed in 2.15s
```
| Test | Old code | New code |
|---|---|---|
| `test_stale_precheck_is_caught_by_the_atomic_guard`: service B's pre-check is forced stale (deterministic race) | **fails** (second irreversible step recorded `ok`, budget overspent) | refused `used 1 of 1`; 1 ok row; the refused step recorded once; chain verifies |
| `test_parallel_processes_never_overspend_a_shared_budget`: 4 processes x 3 `pentest.nmap` on one multi-use grant, budget 3 | passed in this run (the race window is narrow and was not hit), so it is a **guard**, not proof of the old bug | exactly 3 ok across all processes |

## Error envelope / cleanup
Every outcome is explicit: ok, refused (budget, with counts), or `LOOPSERV_ERR_AUDIT` for genuine write failures. The rollback on `BudgetExhausted` releases the
write lock, and connections are closed via `closing()`. Workers in the race test are joined with a timeout.

## Known limitation (unchanged)
The service-wide RLock is held across the step's SQLite work (up to 3 opens, 5 s busy timeout each), so a contended DB slows every loop in the process.
This is bounded by the busy timeout and the MCP call timeout, and is not attacker-triggerable through policy inputs alone (T-03329 review).
