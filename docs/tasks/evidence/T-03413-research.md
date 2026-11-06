# T-03413 Research: Tool Registry & Taxonomy — automated tests

- Date: 2026-11-06
- Question: what automated tests does the tool registry need beyond its existing per-task suites, so that later changes cannot
  quietly break its safety properties?
- Method: inventory of the existing registry tests (`code/aiosh-mcp/tests/test_tool_registry_*.py`, 30 files, ~500 tests), reading the
  precedent from the agent-loop automated-tests epic ([T-03314-spec.md](T-03314-spec.md)), and checking the environment. **No code was changed.**

## A. Facts
- **Existing coverage is example-based.** Every registry task added hand-written cases plus small random corpora:
  - 500 random names in T-03376 / T-03377;
  - 20 000 lookups in T-03370;
  - hostile files in T-03407.
- **No test generates *catalog entries* or *whole configurations* at random.** The validator's seven rules, the alias/collision fold, the
  merge in `more_cautious` and the config precedence are each tested on chosen examples only.
- **Precedent** (T-03314): a stdlib-only, seeded, model-based fuzz. A reference model derived from the spec, not the code, predicts each outcome.
  Failures print the seed and replay exactly (AUTOTEST-INV1..3). Env knobs choose seeds and size. It runs in CI suite #34.
- **Environment:** `hypothesis` is **not installed** (`ModuleNotFoundError`), and adding a dependency needs justification. The precedent shows
  stdlib `random.Random(seed)` is enough.
- **Cross-substrate parity** already exists for TS `ToolClass`, TS `isIrreversible` (T-03368) and TS `toolGlobMatch` (T-03388). The Rust
  `is_irreversible` differs knowingly (research B4.4); nothing tracks that.

## B. Properties worth generating (all stated in the specs)
| # | Property | Source |
|---|---|---|
| P1 | An entry is accepted **iff** it satisfies the seven consistency rules and the name rules | T-03364 §2, T-03369 |
| P2 | A catalog is accepted iff no two names collide under NFKC + casefold + separator fold (an alias may fold onto its own canonical) | T-03369 #6 |
| P3 | `profile(x)` never raises and is never weaker than the legacy name rules, for any `x` | TOOLREG-INV3, TOOLSVC-INV1 |
| P4 | `more_cautious(existing, derived, allow)` never relaxes any hint | TOOLAPI-INV2 |
| P5 | Config mode is strict iff any source asks for strict, says anything unrecognised, or is an unusable file or path; numbers follow the stated precedence and bounds | TOOLREGCONF-INV1/4 |
| P6 | `export_json()` round-trips: export → parse → rebuild gives the same catalog | T-03363 D3 |

## C. Decisions needed
| # | Decision | Recommendation |
|---|---|---|
| D1 | Framework | Stdlib `random.Random(seed)` with a reference model, as in T-03314. No new dependency. |
| D2 | Scope | One property module covering P1–P6, each with its own small oracle written from the spec text. |
| D3 | Size and seeds | Env `AIOSH_TOOLREG_FUZZ_SEEDS` (default `1,2,3`) and `AIOSH_TOOLREG_FUZZ_N` (default 300 cases per property). Budget < 30 s in CI. |
| D4 | Failure output | The seed, property, case index and the minimal input repr, so the case replays exactly. |
| D5 | Rust drift | A tracked, non-failing report of the Rust `is_irreversible` difference (parsed from the source, since the Rust binary is not built here). |
