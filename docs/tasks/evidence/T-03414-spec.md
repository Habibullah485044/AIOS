# T-03414 Specification: Tool Registry & Taxonomy — automated tests

- Date: 2026-11-06
- Adopts [T-03413-research.md](T-03413-research.md) D1–D5. Stdlib only. Everything lives under `code/aiosh-mcp/tests/`.

## 1. Components
| Status | File | Role |
|---|---|---|
| **New** | `tests/tool_registry_model.py` | Spec-derived oracles and generators: `gen_entry_kwargs(rng)`, `entry_should_be_valid(kw)`, `gen_name(rng)`, `legacy_floor(name)`, `gen_annotation(rng)`, `caution(a)`, `gen_config_sources(rng)`, `expected_config(sources)`, `seeds()`, `n_cases()` |
| **New** | `tests/test_tool_registry_properties.py` | P1–P6 over each seed (CI suite #35 picks it up through `-k tool_registry`) |
| **New** | `tests/test_tool_registry_rust_drift.py` | Tracked, non-failing report of the Rust `is_irreversible` difference (parsed from source) |

## 2. Properties (each checked for `n_cases()` generated cases per seed)
- **P1 entry validity.** `ToolEntry(**kw)` succeeds **iff** `entry_should_be_valid(kw)`. The oracle encodes the name regex and length, title rules,
  alias bounds, and rules 1–7 of the operator doc §2, written from the doc text.
- **P2 name collisions.** For a random set of valid entries, `ToolCatalog(entries)` raises `TOOLREG_ERR_DUPLICATE` **iff** two names from
  different entries (or two aliases of one entry) share the fold `NFKC → casefold → [._-]+ → "."`.
- **P3 never weaker.** For random names (valid, malformed, Unicode, case and separator variants of registered names), `profile(n)` and
  `ToolRegistryService.decide(n)` never raise. They are at least as strict as `legacy_floor(n)` (grant set and irreversible set of
  `grant_check` and `is_irreversible`).
- **P4 never relax.** For random `(existing, derived, allow)`, `caution(more_cautious(...))` is at least as cautious as `caution(existing)` in
  every field, and `readOnlyHint` is true only when `allow` holds and `existing` makes no contrary claim.
- **P5 config.** For random combinations of argument, env, file content (valid, invalid, locked, duplicate, BOM, oversize) and bad paths,
  `resolve()` equals `expected_config(sources)` in mode and in every number.
- **P6 export round-trip.** For random valid catalogs, `export_json()` → parse → rebuild entries → `export_json()` is byte-identical.

## 3. Determinism and failure output (AUTOTEST-INV1)
- Seeds come from `AIOSH_TOOLREG_FUZZ_SEEDS` (comma list, default `1,2,3`).
- Cases per property come from `AIOSH_TOOLREG_FUZZ_N` (default 300).
- A failure message carries `seed=…, property=…, case=…` and the input `repr`.

## 4. Invariants
- AUTOTEST-INV2: the oracles are written from the specs and docs, not by calling the code under test.
- AUTOTEST-INV3: tests write only under `tmp_path`, and every env var they set is restored.
- The whole module must run in < 30 s on this host.
