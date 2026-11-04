# T-03313 Research: Agent Loop Hardening — automated tests

- Date: 2026-11-05
- Scope: research only. **No code changed.**

## Facts (verified)
| # | Fact | Source |
|---|---|---|
| F1 | 30 `test_agent_loop_*.py` files plus the helper `agent_loop_grants.py`: 279 passed, 1 skipped in about 40 s. The files are organised per ledger task (scaffold/impl/unit/integration/security/hardening) and assert **hand-picked scenarios**. | `code/aiosh-mcp/tests/`, `pytest -k agent_loop` |
| F2 | CI (`tools/ci_suites.py` suite `agent_loop_integration`) runs only **4** of those 30 files. Unit, hardening and security files for the data model, service, CLI, MCP and config never run in CI. | `tools/ci_suites.py:190-196` |
| F3 | No test generates **random operation sequences** against the FSM. The invariants (LOOPDATA-INV1/INV2, terminal states absorbing, exactly one audit row per consequential event, chain verifies) are only checked on the paths someone thought of. The 7 independent-audit findings (#419..#422) were all paths nobody had written a test for. | F1; PRs #419..#422 |
| F4 | `hypothesis` is **not installed** and `pyproject.toml` has no test extras. Seeded random generation from the stdlib (`random.Random(seed)`) needs no new dependency and is reproducible from the seed. | `python -c "import hypothesis"` -> ModuleNotFoundError |
| F5 | The TS issuer -> Python redeemer path (cross-substrate) was verified **by hand** in T-03291. No automated test covers it, although `node` and `code/aiosh-cli/dist/cli.js` exist on this host. | T-03291 evidence |
| F6 | Concurrency is covered only for raw audit writes (`test_audit_chain_concurrency.py`) and for threads within one service. There is nothing for several **processes** running loops against one ring (the deployment shape: MCP server + CLI + TS CLI). | test files |
| F7 | Precedent: `aiosh_mcp/model_backend_adapters_automated_tests.py` put a test harness **inside the production package** (it ships to users). The structure review flagged this pattern. | file header; structure review |

## Upstream references
- Python `random` (reproducible streams with `Random(seed)`): https://docs.python.org/3/library/random.html
- Model-based / stateful testing (generate operation sequences, check invariants after each step); the idea is from Hypothesis'
  `RuleBasedStateMachine`: https://hypothesis.readthedocs.io/en/latest/stateful.html (concept only, not a dependency)
- SQLite locking and `BEGIN IMMEDIATE` (relevant to the multi-process stress test): https://sqlite.org/lang_transaction.html

## Assumptions
- A1: About 200 random operations x several seeds fits CI's per-suite timeout (`DEFAULT_TIMEOUT_S`) on a laptop.
- A2: Skipping the TS cross-substrate test when `node` or `dist/` is missing is acceptable; it must never be a silent pass, so it reports a skip reason.

## Decisions needed (for T-03314)
- D1: Add a **seeded model-based fuzzer** for `AgentLoopService` against the real `PepCapabilityGate` and a temp ring. Check invariants after
  every operation. A failure prints the seed and the op log so it can be replayed. (Recommended.)
- D2: Add a **multi-process stress** test: N processes each run loops on one ring; afterwards the chain verifies, rows per run equal the ops,
  and loop ids are unique. (Recommended.)
- D3: Add an **automated cross-substrate** test: `aiosh grant create` (TS) mints a grant and the Python service redeems it; skip with a reason if node or dist is missing. (Recommended.)
- D4: Register the **whole** agent-loop battery in CI as one suite (`pytest -k "agent_loop or audit_chain_concurrency or grant_scope"`). (Recommended.)
- D5: Keep the harness under `tests/`, not in the shipped package (F7). Stdlib only, no new dependency (F4).
