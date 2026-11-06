# T-03416 Evidence: Tool Registry & Taxonomy — automated tests Implementation

- Date: 2026-11-06
- Spec: [T-03414-spec.md](T-03414-spec.md).
- `code/aiosh-mcp/tests/tool_registry_model.py`: spec-derived oracles and seeded generators (stdlib only).
- `code/aiosh-mcp/tests/test_tool_registry_properties.py`: P1–P6, each × 3 seeds × 300 cases.

## Properties (each oracle is written from the operator doc, not from the code)
| # | Property | Generated input |
|---|---|---|
| P1 | `ToolEntry(**kw)` accepted **iff** the doc's name, alias and title rules and consistency rules 1–7 hold | random names (valid, risky prefixes, malformed, non-str), aliases (0–9, bad chars, a list), titles (empty, 65 chars, ESC, bidi, U+2028, C1), every enum value, non-bool flags |
| P2 | `ToolCatalog` raises `TOOLREG_ERR_DUPLICATE` **iff** two names share the fold (NFKC → casefold → `[._-]+`→`.`) other than an alias folding onto its own canonical | name sets built from separator, case and suffix variants |
| P3 | `profile()` and `decide()` never raise and are never weaker than today's grant and irreversible rules. `decide()` is at least as strict as `profile()`, and an unknown name is fail-closed | registered names, upper case, separator swaps, fullwidth, risky prefixes, `None`/int/bytes/NUL/300 chars/bidi |
| P4 | `more_cautious` never relaxes: read-only only if allowed and no contrary claim; destructive never dropped; idempotent never newly claimed; open world sticky | all `None`/`True`/`False` combinations of the four hints, plus `None` |
| P5 | `resolve()` equals the doc §6e result for mode and every number | argument/env modes (incl. fullwidth, blank, typos), env numbers (blank, spaces, out of bounds, garbage, `3.5`), files (valid, locked, unknown, wrong types, duplicate keys, BOM, UTF-16, bad JSON, array, oversize) in env, default, missing and bad (`CON`, `../`, `\??\`) locations |
| P6 | export → parse → rebuild keeps **every field** (entries equal) and re-exports byte-identically; every exported entry has exactly the doc §2 fields | random valid catalogs of up to 30 entries |

Failures print `seed=… property=… case=…` and the input, so they replay exactly (AUTOTEST-INV1).

## Found while writing the oracles
The operator doc's rule-7 list omitted the bare name **`pentest`**, which the code (`IRREVERSIBLE_NAMES`) and the agent-loop gate treat as
irreversible. The doc now lists it.

## Results
```
$ python -m pytest tests/ -k tool_registry -q
525 passed, 1 skipped, 1437 deselected, 1 warning in 121.11s (0:02:01)
property module alone (3 seeds x 300): 18 passed in ~12-20 s   (budget 30 s)
```

## Mutation check
Each mutation was applied to a copy of the package (on `PYTHONPATH`) with the repo untouched. All 3 seeds were run.
| Mutation | Result |
|---|---|
| none (control) | 18 passed |
| M1 consistency rule 3 removed (network scope without open world) | 2 failed |
| M2 separator fold removed from the collision key | 3 failed |
| M3 `decide()` drops the catalog's grant requirement | 3 failed |
| M4 annotation merge drops open-world when granting read-only | 3 failed |
| M5 file mode not part of strictest-wins | 3 failed |
| M6 export drops `idempotent` | 3 failed |

The first draft let **M3 and M6 survive**:
- P3 compared `decide()` only with the legacy floor;
- P6 compared export with export.

Both were strengthened before shipping: `decide()` ≥ `profile()`; rebuilt entries equal the originals; exported fields equal the doc.
