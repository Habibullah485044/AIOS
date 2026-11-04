# T-03319 Security Review: Agent Loop Hardening — automated tests

- Date: 2026-11-05
- Scope: the test battery itself: `agent_loop_grants.py` (incl. the `AllowAllGate` double), `agent_loop_model.py` (fuzzer),
  the cross-substrate test (spawns `node`), and CI suite #34.
- Threats for test infrastructure:
  - escaping the sandbox: writing to the developer's real `~/.aios/audit.db`, or leaving artefacts that `git add -A` ships
  - a test double reaching production code
  - realistic fake secrets tripping scanners

## Findings
| # | Severity | Finding | Status |
|---|---|---|---|
| A1 | **Medium (happened)** | A test helper created `unused.db` in the package dir, and `task_pr.py` (`git add -A`) committed it in #431. | Fixed in #432: file removed; `*.db`/`-wal`/`-shm` gitignored; the ship script refuses stray `.db`/`.zip`. **New guard:** `test_battery_slice_never_touches_home_or_tree` asserts no new files in the package tree. |
| A2 | Medium (latent) | The `aios.agent_loop.config` degraded row (T-03310) and any `open_db()` with no path write to the **default** `$AIOSH_HOME`. A test that forgets to isolate would write rows into the developer's real ring, which cannot be removed afterwards without breaking the chain. | Verified **not happening**: the full battery (347 tests) ran with `HOME`/`AIOSH_HOME` pointed at an empty sentinel. The sentinel stayed empty, and the real ring had 45530 rows before and after. **New guard:** the same check runs as a test on a representative slice. A negative probe (a test calling `open_db()`) **does** leave `audit.db` in the sentinel, so the guard detects leaks. |
| A3 | Medium (latent) | `AllowAllGate` redeems anything and allows every tool. If production code ever imported it, PoR I-2 would be void. | Not happening. **New guard:** a static test asserts no `aiosh_mcp/*.py` references `AllowAllGate`, `agent_loop_grants`, `agent_loop_model` or `mint_grant`, and that `pyproject.toml` packages only `aiosh_mcp*` (tests are not shipped). |
| A4 | Low | The cross-substrate test runs `node` from `PATH` (`shutil.which`). A poisoned PATH in CI could run another binary. | Accepted: the same trust as the TS CLI build step. The test only passes `--to/--tools/--ttl` literals and a temp `AIOSH_HOME`; no secrets are in its env beyond the inherited CI env. |
| A5 | Info | Masking tests contain realistic fake credentials (`github_pat_...`, `AKIAIOSFODNN7EXAMPLE` (AWS's documented example), `xoxb-...`). | Accepted: required to test masking. GitHub push protection accepted every push. They are fixtures only and match no real account. |
| A6 | — | Seeds and op counts come from env (`AIOSH_LOOP_FUZZ_SEEDS/OPS`) via `int()`. | Not exploitable: a bad value fails test collection loudly. |

## PoR standing rule
The battery adds no state-changing production path. Every grant it mints lives in a temp DB. `AllowAllGate` is test-only (A3 guard).
**No known bypass.**

## Guard tests (`tests/test_agent_loop_battery_isolation.py`, 3 cases, also in CI suite #34 through `-k agent_loop`)
1. production code never references the test doubles
2. tests are not packaged
3. the battery slice (fuzz seed 11 x 60 ops, CLI/service/data-model integration) under a sentinel HOME writes nothing there and adds no files to the package tree
