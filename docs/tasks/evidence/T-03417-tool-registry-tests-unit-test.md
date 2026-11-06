# T-03417 Evidence: Tool Registry & Taxonomy — automated tests Unit Test

- Date: 2026-11-06
- New `code/aiosh-mcp/tests/test_tool_registry_properties_unit.py` (45 tests), standalone.
- Purpose: if a property-test oracle were wrong *in the same way* as the code, both would pass. These tests pin the oracles from
  T-03416 to **hand-worked examples taken from the operator doc**, and check the generators.

## Coverage
| Area | Cases |
|---|---|
| P1 entry oracle | the reference entry valid, plus at least one hand-worked violation of **each** doc rule 1–7 (incl. the offline pentest tool allowed with path scope, and rule 7 for `shell.exec` and the bare `pentest`); name rules (upper case, 65 chars, `a..b`); alias rules (bad char, 9 aliases, list); title rules (empty, 65 chars, bidi); a non-bool flag |
| P2 collision oracle | alias onto own canonical (allowed), two aliases of one entry, a cross-entry alias differing only in case and separator, distinct names; fold examples (`AIOS_Fs-read`, fullwidth, `a__b`) |
| P3/P4/P5 oracles | legacy floor for 7 names (incl. case-sensitive grant vs case-insensitive irreversible); MCP annotation defaults; mode votes (blank, case, fullwidth, typo, non-str); `expected_config` for defaults, a missing file, env strict over file shadow, precedence and clamping, a locked key |
| Generators | same seed → same sequence; across 900 generated entries **every rule 1–7 is violated at least once** |

## Results
```
$ python -m pytest tests/test_tool_registry_properties_unit.py -q
45 passed in 2.70s
```

## Oracle mutations (applied one at a time to the model, then reverted)
| Mutation of the oracle | Result |
|---|---|
| rule 4 removed from `entry_should_be_valid` | 1 failed |
| bare `pentest` removed from the irreversible names | 1 failed |
| separator / NFKC fold removed from `fold` | 3 failed |
| "unusable config counts as strict" removed from `expected_config` | 1 failed |
