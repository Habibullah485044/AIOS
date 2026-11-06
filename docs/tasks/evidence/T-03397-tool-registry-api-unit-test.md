# T-03397 Evidence: Tool Registry & Taxonomy — API surface Unit Test

- Date: 2026-11-06
- New `code/aiosh-mcp/tests/test_tool_registry_api_unit.py` (15 tests), standalone.

## Coverage
| Area | Cases |
|---|---|
| Argument boundaries | the `aios_tool_registry_decide` schema accepts names of 1 and 256 chars and `require_grant`; it rejects 257 chars, empty, non-string and missing names |
| Behaviour | `require_grant=true` removes the expected `fs.read` grant disagreement; unknown names are fail-closed and reported `unregistered`; `stats` counts each decision and never contains a queried name (hashed samples only) |
| Merge edge cases | an explicit `readOnlyHint=true` is withdrawn when the catalog disallows it; an explicit `false` is never upgraded; the module's own title is kept; open-world is sticky |
| Annotation pass | applying twice gives the second pass `0 applied / 3 unchanged`; on the live server the import-time pass is a fixed point (re-applying changes nothing, same objects) |

## Results
```
$ python -m pytest tests/test_tool_registry_api_unit.py -q
15 passed in 2.31s
```

## Mutations (applied one at a time to `tool_registry_api.py`, then reverted; unit + impl tests)
| Mutation | Result |
|---|---|
| M1: ignore `allow_read_only` (any catalog read-only becomes `readOnlyHint`) | 2 failed |
| M2: take the catalog's destructive/idempotent hints instead of the cautious merge | 4 failed |
| M3: open-world not sticky | 8 failed |
