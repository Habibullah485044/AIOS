# T-03320 Evidence: Agent Loop Hardening — automated tests Hardening

- Date: 2026-11-05

## Added
| Item | Detail |
|---|---|
| **Multi-process stress** (spec §3) | `tests/test_agent_loop_stress.py`: 4 processes x 5 loops x 6 turns (ok and refused steps alternate) + complete, on **one** ring. Each worker reports through a queue and never hangs the parent (`BaseException` is reported). The parent joins with a 180 s timeout, then kills, and an alive worker is a failure. Asserts exact row counts per tool (20 starts, 120 steps, 20 completes, 20 redeems), unique loop ids, `count(*) == count(DISTINCT prev_hash)`, and `verify()` ok. |
| **Fuzzer time budget** | `run_and_check(..., max_seconds=120)` (env `AIOSH_LOOP_FUZZ_MAX_S`). Exceeding it is a **reported failure** ("possible hang or lock contention"), never a silent early pass. Tested with a 0 s budget. |

## The stress test catches the real bug
Mutation: the #419 `BEGIN IMMEDIATE` around the chain-head read was removed:
```
E           AssertionError: chain forked under concurrency
E           assert 180 == 143
1 failed
```

## Timeouts / cleanup inventory (whole battery)
- Every subprocess call has a `timeout`: CLI subprocess 60 s, stdio MCP via the client context manager, cross-substrate `node` 60 s, isolation slice 300 s, config import/hang probes 20-120 s.
- Multiprocessing workers are joined with a timeout and killed if still alive.
- Every DB lives under `tmp_path`. `closing()` is used everywhere. The isolation guard (T-03319) asserts no files are left in the package tree.

## Tests
```
8 passed in 25.57s
```
