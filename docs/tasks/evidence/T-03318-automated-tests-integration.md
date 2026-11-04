# T-03318 Evidence: Agent Loop Hardening — automated tests Integration

- Date: 2026-11-05

## Wired into the real call path
| Item | Change |
|---|---|
| CI registry | `tools/ci_suites.py` suite **#34 `agent_loop_battery`** (tail append). It runs **all** agent-loop tests plus the chain-concurrency, grant-scope and secret-masking regressions: `pytest -k "agent_loop or audit_chain_concurrency or grant_scope or secret_masking" code/aiosh-mcp/tests`. Timeout `RUST_SMOKE_TIMEOUT_S` (2x default). Before this, CI ran 4 of 30 agent-loop files (T-03313 F2). |
| Registry self-test | `tools/test_ci_suites.py`: frozen order plus `agent_loop_battery`, count 33 -> 34. PASS (W1..W7). |
| Cross-substrate | New `tests/test_agent_loop_cross_substrate.py` automates the T-03291 by-hand check. A grant minted by the **TS CLI** (`node dist/cli.js grant create`) under a temp `AIOSH_HOME` is redeemed by the **Python** service, which then runs ok/refused steps and completes. TS scope (a grant without `aios.agent_loop.start`) and single-use are honoured by Python. TS and Python rows share one chain that verifies. If `node` or `dist/` is missing the test skips with the reason. |

## Integration smoke (exact CI command, repo root)
```
$ python3 -m pytest -q --no-header -p no:cacheprovider -k "agent_loop or audit_chain_concurrency or grant_scope or secret_masking" code/aiosh-mcp/tests
347 passed, 1 skipped, 908 deselected, 1 warning in 72.05s
```
The 1 skip is the POSIX-only FIFO config test. The cross-substrate tests **ran** on this host (2 passed; `node` and `dist/cli.js` present).
