# T-03337 Evidence: Agent Loop Hardening — observability Unit Test

- Date: 2026-11-05
- Test file: `code/aiosh-mcp/tests/test_agent_loop_observability_unit.py` (13 cases, hand-built rings, standalone)

| Area | Cases |
|---|---|
| Row selection | non-agent-loop and **lookalike** tools (`aios_agent_loop.step`, `aios.agentXloop.step`, `aios.agent_loopX`) are ignored |
| Window | the edges 1 and 100000; the newest-N selection is ordered oldest first |
| Durations | rows without or with malformed `duration_ms` are excluded from the percentiles; percentile helper: 5 cases incl. empty, single value, 1..100 |
| Aggregates | degraded-config rows; irreversible grouping per hashed grant (no raw grant ids); a refused irreversible step is not counted; health `degraded` |
| Failures | corrupt DB raises `ObservabilityReadError` (`LOOPOBS_ERR_READ`); a DB without `audit_ring` gives empty metrics |
| Logging | level filtering; reason masked (`Bearer sk-...`) and truncated to 200 characters; structured `event` field |

## Defect found and fixed by these tests
`read_loop_history` (and the first draft of the metrics filter) selected rows with `LIKE 'aios.agent_loop.%'`. Because `_` is a LIKE
wildcard, a lookalike tool `aios.agentXloop.*` carrying the same `loop_id` would appear in a loop's history. Both now filter with
`substr(tool, 1, 16) = 'aios.agent_loop.'`. A new test, `test_history_ignores_lookalike_tools`, fails on the old gate code.

## Fails when broken (mutations)
| Mutation | Result |
|---|---|
| metrics filter changed back to `LIKE` | `FAILED test_non_agent_loop_rows_are_ignored` (1 failed, 12 passed). The first decoy (`aios_agent_loop`) did **not** catch it, because the wildcard sits in the pattern; the decoy was corrected to `aios.agentXloop` |
| old `read_loop_history` (LIKE) | `test_history_ignores_lookalike_tools` fails |

```
13 passed in 0.72s
```
