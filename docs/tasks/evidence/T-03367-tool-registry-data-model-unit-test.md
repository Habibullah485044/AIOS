# T-03367 Evidence: Tool Registry & Taxonomy — data model Unit Test

- Date: 2026-11-06
- New `code/aiosh-mcp/tests/test_tool_registry_data_model_unit.py` (59 tests), standalone.

## Coverage
| Area | Cases |
|---|---|
| Boundaries | name length 64 accepted / 65 rejected (canonical and MCP), empty names, 8 vs 9 aliases, title 64 vs 65, catalog size at / over the limit |
| Invalid input | whitespace, `/`, leading digit, leading or trailing dot, zero-width space and ligature (`ﬁ`) in canonical names; fullwidth MCP lookalikes |
| Primary failure modes | case variants cannot alias (3 forms); duplicate alias inside one entry; lookups on `None` / int / bytes / padded / upper-case / 10 000-char names never fail open; hostile names (ANSI escape, bidi override, 10 KB) are not echoed raw or escaped and messages stay < 200 chars; network-prefix scoping has a dot boundary (`pentesting.x` is path-scoped); entries, the catalog and its name map cannot be mutated; 2 000 random names never crash or register |
| Export | `export_json()` → rebuilt catalog → identical JSON; ASCII only |
| **Drift (permanent)** | for every catalog entry: `irreversible` equals `audit_client.grant_check`'s name rule **and** `agent_loop_policy.is_irreversible`; network scope equals the `pentest.`/`network.` rule; annotations are consistent with the taxonomy |

## Results
```
$ python -m pytest tests/test_tool_registry_data_model_unit.py -q
59 passed in 2.07s
```

## The tests fail when the feature is broken (mutations applied one at a time, then reverted)
| Mutation | Result |
|---|---|
| M1: `_fold` returns the name unchanged (no case folding) | 4 failed |
| M2: `unknown_profile` fails open (additive, reversible, no grant) | 2 failed |
| M3: error messages echo raw names | 1 failed. The first draft missed this because `!r` escapes control characters; the test now uses a 10 KB hostile name and checks escaped forms too |

The tool-registry tests now also run in my pre-ship gate together with the agent-loop battery.
