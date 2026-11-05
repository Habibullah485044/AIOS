# T-03360 Evidence: Agent Loop Hardening — recovery & validation Hardening

- Date: 2026-11-06
- Scope: `agent_loop_recovery` error paths, timeouts and resource cleanup, plus the shared
  `audit_client.open_db` / `grant_redeem` helpers it depends on.
- Method: I probed each failure mode against the T-03359 code (`probe60.py`: malformed grant budget,
  failing write, locked DB), fixed what failed, and wrote a test per mode. Each test was run against the
  pre-fix code.

## Gaps found and fixed
| Failure mode | Before | After |
|---|---|---|
| Grant row with a non-integer `max_irreversible` | `validate_ring` raised a raw `ValueError`. That also broke `metrics`, which only catches `RecoveryError`. | Reported as a new problem kind `budget_invalid` (grant id hashed). The report still completes. |
| Grant row whose `scope_json` is not JSON | raw `JSONDecodeError` | `RecoveryError(LOOPREC_ERR_READ)` with the exception type only |
| Validation over a very large ring | no time bound (the MCP call timeout abandons the thread but the query keeps running) | SQLite progress handler plus explicit checks between phases. Default **10 s** budget, then `LOOPREC_ERR_READ` "use a smaller window". The read-only connection is always closed. |
| A `recovered` row write fails (disk full / I/O) | raw `sqlite3.OperationalError`, and which runs were already closed was lost | New **`LOOPREC_ERR_WRITE`**: "failed after N of M run(s) closed". `RecoveryError.recovered` lists the committed ones, and the MCP and CLI envelopes return them in `data.recovered`. The open transaction is rolled back, so no lock is left held. Re-running recovery finishes the job. |
| Locked DB during recovery | ~5.6 s, then a raw `OperationalError` | Bounded by the configured `db_busy_timeout_ms` (`open_db(timeout=...)`, new optional argument, default unchanged), then `LOOPREC_ERR_WRITE`. The grant is **not** consumed, so a retry works. |
| **`grant_redeem` forced `busy_timeout = 5000`** on the caller's connection | **Shared bug:** every grant redemption, including agent-loop start, ignored the configured `db_busy_timeout_ms` (T-03310). | It sets 5000 only when the connection has no wait configured, so the caller's value is kept. |
| Redemption whose audit row cannot be written | reported as `LOOPSERV_ERR_UNAUTHORIZED` (exit 3) | `LOOPREC_ERR_WRITE`. `grant_redeem` already un-redeems a single-use grant in that case. |
| `total_timeout_ms` on a start row that is negative / NaN / not a number | a negative value made the run recoverable immediately | clamped to the LoopConfig range [5 s, 1800 s]; NaN or unparseable falls back to 1800 s |

Error envelope: every path above now ends in a documented code (`LOOPREC_ERR_READ`, `LOOPREC_ERR_WRITE`,
`LOOPSERV_ERR_UNAUTHORIZED`). `ERROR_MEANINGS` and the operator spec §6 both list `LOOPREC_ERR_WRITE`; the
two-way doc tests enforce that.

Cleanup: `validate_ring` closes its read-only connection in `finally`. `recover_orphans` uses `closing()`
and rolls back any open transaction per run (`try/finally`). No temp files or child processes are involved.

Fail-open honesty (ADR-0035 §F-2): recovery never "succeeds quietly". A failure after partial progress
returns an error code together with the exact list of runs whose `recovered` rows were committed.

## Tests (`code/aiosh-mcp/tests/test_agent_loop_recovery_hardening.py`, 7)
| Test | Old code | New code |
|---|---|---|
| malformed grant budget is a problem, not a crash | **fails** | passes |
| unparseable grant row is a read error | **fails** | passes |
| validation deadline | **fails** | passes |
| write failure: explicit, partial list, lock released, re-run finishes | **fails** | passes |
| locked DB: bounded by config, explicit, grant not consumed | **fails** | passes |
| CLI reports write failure in the envelope | **fails** | passes |
| malformed timeout cannot make a run recoverable early | **fails** | passes |

Result on pre-fix code: **7 failed**. On the fixed code: **7 passed**.

## Verification
- Agent-loop battery: **526 passed, 1 skipped**.
- Wider audit/PEP/grant/redeem/dispatch/capability tests: 133 passed. All 43 failures are the known
  Windows baseline `FileNotFoundError: [WinError 2]` (unbuilt Rust `aiosh-mcp.exe`); **0 others**.
- `python tools/test_por_conformance_suites.py`: **CONFORMANT: C1..C6 PASS**.
