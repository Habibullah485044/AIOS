# T-03280 Evidence: Agent Loop Hardening Core Service — Hardening

- Date: 2026-11-05
- Files: `aiosh_mcp/agent_loop_service.py`, `aiosh_mcp/agent_loop_gate.py`,
  `tests/test_agent_loop_core_service_hardening.py` (13 cases)

## Failure modes -> explicit, auditable errors
| Failure | Behaviour | Error code |
|---|---|---|
| Audit write fails on `start` | Loop **not registered** (an unaudited loop must not exist); grant redemption row already in the ring | `LOOPSERV_ERR_AUDIT` |
| Audit write fails on `step`/`abort`/`timeout` | Loop terminated (ABORTED, reason names the failed event); later turns get `LOOPSERV_ERR_TERMINATED` | `LOOPSERV_ERR_AUDIT` |
| Gate/DB error during redemption | Start refused (fail closed) | `LOOPSERV_ERR_GATE_UNAVAILABLE` |
| Gate/DB error during tool scope check | Step recorded as `refused` and audited (fail closed) | `LOOPSERV_ERR_POLICY_REFUSED` + `GATE_UNAVAILABLE` |
| Oversized/malformed input | Rejected before any state change | `LOOPSERV_ERR_INVALID_INPUT` |
| Registry full | Oldest terminated loops evicted; refuse if all active | `LOOPSERV_ERR_CAPACITY` |

Fail-open is never used, so ADR-0035 §F-2's "honest audit row on fail-open" case does not arise;
every fail-closed refusal of a tool call still writes an audit row.

## Caps and bounds
- `action_intent` <= 4096 chars, abort `reason` <= 1024 chars
- `tool_name` must match `[A-Za-z0-9_.-]{1,128}` (rejects `fs.write; rm -rf /`)
- `tokens_consumed` int in [0, 1_000_000], bools rejected
- registry capacity = `MAX_REGISTRY_CAPACITY` (256) with terminated-first eviction
- SQLite `busy_timeout = 5000 ms`: bounded wait on a locked DB instead of an immediate failure

## Resource cleanup and concurrency
- Every gate DB access uses `contextlib.closing`. `test_no_db_handles_leak_on_error_paths` drives the
  refused-start, refused-step and abort paths, then deletes the DB file. Windows refuses to delete an
  open SQLite file, so a successful delete shows no handle leaked.
- `threading.RLock` serialises mutations. In the concurrency test, 8 threads x 10 turns keep step indices
  contiguous and `validate_invariants()` holds.
- The service starts no child processes and creates no temp files.

## Run
```
cd code/aiosh-mcp && python -m pytest tests/ -k agent_loop -q
87 passed, 909 deselected in 5.07s
```
