# T-03377 Evidence: Tool Registry & Taxonomy — core service Unit Test

- Date: 2026-11-06
- New `code/aiosh-mcp/tests/test_tool_registry_service_unit.py` (27 tests), standalone.

## Bug found by these tests (fixed here)
`decide()` is specified never to raise, but it **raised `AttributeError`** for a classification that is not a dict (`"c3"`, `7`,
`{"c_flags": "c3"}`), and it counted a truthy non-bool (`{"c3": "yes"}`) as C-3. Fixed with `_c3()`: only a dict whose `c_flags` is a
dict with `c3 is True` counts. Before the fix, 4 of the tests failed.

## Coverage
| Area | Cases |
|---|---|
| Malformed input | 10 classification shapes (None, empty, list, str, int, non-dict `c_flags`, truthy non-bool `c3`) never raise; only a real `True` marks a call irreversible |
| Boundaries | modes `shadow`/`strict`, case and whitespace (`" STRICT "`), the env default, and rejected values (`""`, `off`, `enforce`, `1`) give `TOOLSVC_ERR_MODE`; an empty catalog makes every name unregistered and fail-closed; scope-`none` entries keep the legacy scope |
| Concurrency | 16 threads × 2 000 decisions with a 1 µs switch interval: counters exact (32 000 / 16 000), samples capped at 50 and deduplicated |
| Isolation | `stats()` returns copies; callers cannot change the counters |
| Logging | a closed stderr never breaks a call; a hostile name (a token-shaped `ghp_…`, an embedded newline plus forged JSON, 500+ chars) produces exactly **one** line, masked and ≤ 64 chars; a non-`str` tool is logged by type only |
| Strict mode | enforcement fields equal the decision's (it only tightens) |

## Results
```
$ python -m pytest tests/ -k tool_registry -q
166 passed, 1437 deselected, 1 warning in 16.66s
```

## Mutations (applied one at a time, then reverted)
| Mutation | Result |
|---|---|
| `stats()` returns the live dict/list instead of copies | 1 failed |
| `report()` logs the raw tool name (no masking or bound) | 1 failed |
| counters updated **without the lock** | **not detected.** 3 runs passed even with a 1 µs switch interval. CPython's GIL makes the `+=` race too rare to show reliably. The lock stays, because it is correct; this test checks exact counts but cannot prove the lock is necessary on this interpreter. |
