# T-03277 Evidence: Agent Loop Hardening Core Service — Unit Test

- Date: 2026-11-05
- Test file: `code/aiosh-mcp/tests/test_agent_loop_core_service_unit.py` (standalone, 18 cases)

## Coverage
| Area | Cases |
|---|---|
| Valid input | multi-turn progression, token/iteration accounting |
| Invalid input | 6 parametrized bad configs (bad loop_id incl. shell metachars, out-of-range bounds); empty/whitespace capability token on all 3 mutating methods |
| Boundary | `max_iterations=1` terminates after one turn; `total_timeout_ms=5000` (minimum) watchdog |
| Primary failure modes | duplicate loop, unknown loop (3 methods), terminated loop, policy refusal, consecutive-failure breaker, secret masking |

## Bug found and fixed by these tests
`advance_turn` tripped the total-timeout watchdog with `transition_to(FAILED)` while the loop
was in `OBSERVE`. `OBSERVE -> FAILED` is not a legal edge in `VALID_TRANSITIONS`, so the
watchdog raised a raw `ValueError` instead of `LOOPSERV_ERR_TIMEOUT` and left the loop
un-terminated. Fixed by terminating via `ABORTED` (legal from every non-terminal state).

## Fails when the feature is broken
Reverting `agent_loop_service.py` to `main` makes `test_core_service_watchdog_timeout` fail
(`1 failed, 6 passed` on the original 7-case file).

## Run
```
cd code/aiosh-mcp && python -m pytest tests/test_agent_loop_core_service_unit.py -q
18 passed in 0.33s
```
