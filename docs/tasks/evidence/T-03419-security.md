# T-03419 Security Review: Tool Registry & Taxonomy — automated tests

- Date: 2026-11-06
- Scope: the property suite, the registry's safety net (`tests/tool_registry_model.py`, `test_tool_registry_properties*.py`,
  `test_tool_registry_rust_drift.py`), plus the catalog policy questions it raised.
- Method:
  - An **independent reviewer subagent** applied security-relevant mutations to a *copy* of the package and showed which ones the suite
    let through. It also measured how often each property actually exercised its rule.
  - I reproduced the headline claims before fixing: P1 had 3, 4 and 1 valid entries out of 300 per seed; the agent-loop rule says `shell`/`process` are
    irreversible but the oracle and catalog did not; backup/release were reversible; `AIOSH_TOOLREG_FUZZ_SEEDS=","` gave "6 skipped", exit 0.
  - I re-ran every mutation after the fixes.

## Code findings (security)
| # | Sev | Finding | Status |
|---|---|---|---|
| S1 | **Medium** | **`aios.backup.create` and `aios.release.generate` were not irreversible in the catalog**, while the Rust PEP counts them irreversible. Release overwrites `aios_<os>_<version>.iso` in place. Backup copies data out, including audit and memory, and once filled the disk. In strict mode an agent could run any number of them under a grant capped at N irreversible actions. | **Fixed:** both irreversible and grant-required. The Rust drift list `CATALOG_WEAKER` is now empty. Two older equality tests list them explicitly as *stricter than Python*. |
| S2 | **Medium** | **Rule 7 missed names that today's enforcement treats as irreversible:** the bare `process` and `shell` (agent-loop policy) and the Rust PEP's positive list. The validator, and the oracle, would accept a reversible, grant-free `shell` entry, which could then be advertised `readOnlyHint=true`. | **Fixed:** rule 7 is now the union of `grant_check`, `agent_loop_policy` and Rust `pep::is_irreversible`, without Rust's reversible exceptions. The doc §2 rule 7 lists them all. There are code tests for 6 such names. |

## Test-suite findings
| # | Sev | Finding | Fix |
|---|---|---|---|
| T1 | **High** | **P1 was nearly vacuous:** only 1–4 of 300 cases per seed were valid. Deleting rule 7 (or rule 1) passed the whole property suite. | P1 cases are now a mix: 30% targeted breakers (a plain valid entry with **exactly one** rule broken), 45% valid-plus-one-field-change, 10% valid, 15% fully random. That gives 146–171 valid per seed. A unit test requires every rule **broken alone** for each seed. 20/20 extra seeds pass it. |
| T2 | Medium | P4 compared the merge only with `existing`, so a merge that ignored the catalog survived. 20% of cases were skipped. | P4 also checks against `derived`: destructive and open world sticky from either side, idempotent only if both claim it. No skipped cases. |
| T3 | Medium | Weakening a seed entry's grant flag passed everything, because no name rule covers most entries. | New `test_tool_registry_seed_lock.py` pins (effect, irreversible, grant, scope, open world) of all 73 entries. Any change must be made in the test, in the same reviewed PR. |
| T4 | Medium | The Rust drift parser silently ignored constructs it didn't model (`ends_with` made `pentest.nmap` reversible, unnoticed). It also turned into a skip when the package was installed elsewhere. | Every token in the function body must be modelled, otherwise the test fails. `pep.rs` is located from the test file, and a missing file fails instead of skipping. |
| T5 | Medium | `AIOSH_TOOLREG_FUZZ_SEEDS=","` (or empty) skipped every property with exit 0, a silent CI bypass. | `seeds()` / `n_cases()` raise on empty or < 1. A unit test covers it. |
| T6 | Low | The P2 oracle copied the implementation's single pass, and its generator never produced separator runs. | P2 is now a pairwise statement of the doc rule, and the generator adds `__`, `-.`, `_.` runs. The independent oracle exposed a wording point: several aliases that all spell an entry's own canonical are allowed (as the code does). NFKC was dropped from the generator because names are ASCII by the doc's regexes, so NFKC can never apply to a registered name. |
| T7 | Low | P6 mostly exported empty catalogs (79 of 90 cases). | P6 builds catalogs of up to 40 valid entries and asserts the size (max ≥ 10, mean ≥ 3). |
| T8 | Low | Process-wide service state (singleton, report de-dup, warnings) and the host's `$AIOSH_HOME` config could leak into tests. | `conftest.py` resets all registry process state around every test, and the property module isolates `AIOSH_HOME`. |
| T9 | Low | P3 never varied the caller's `require_grant` or classifier C-3, so `decide()` dropping either passed the property suite. | P3 randomises both and asserts neither is ever dropped. |

## Mutation results (a copy of the package first on `PYTHONPATH`; property, unit, seed-lock and integration suites, 76 tests)
| Mutation | Before (reviewer) | After |
|---|---|---|
| control (none) | — | 76 passed |
| A rule 7 removed | **passed** | 3 failed |
| B merge ignores the catalog | **passed** | 3 failed |
| C seed grant weakened (`aios.mcp.core.dispatch`) | **passed** | 1 failed |
| D Rust `ends_with` construct | **passed** | fails (parser refuses unknown construct) |
| E fold no longer collapses runs | **passed** | 3 failed |
| F title `isprintable` check removed | **passed** | 3 failed |
| I `decide()` drops the caller's `require_grant` | **passed** | 3 failed |
| J `decide()` drops C-3 | **passed** | 3 failed |
| K config path hygiene removed | **passed** | 3 failed |
| M3 / M5 (from T-03416) | caught | 3 failed each |

## Instruction checklist (verified 2026-11-13)
| Instruction | Result |
|---|---|
| Input validation | Validator rules 1–7 are each broken alone per seed (T1); title control/bidi text is rejected (mutation F caught). |
| Path / argument injection | `$AIOSH_HOME` config path hygiene is covered (mutation K caught); the property module isolates `AIOSH_HOME` (T8). |
| Untrusted content | Catalog config is the only untrusted input; names are ASCII by regex, titles pass `_FORBIDDEN_TEXT` + `isprintable`. |
| PEP gating | P3 asserts `decide()` never drops the caller's `require_grant` or C-3 (mutations I, J caught). `aios.backup.create` / `aios.release.generate` run through `server._recorded_call(require_grant=True)` (server.py:225, 259): classifier, then PEP, then one result audit row. |
| Audit rows | The tests add no state-changing path. Refusals are written by `dispatch()`; successes by `commit()` in `_recorded_call` (server.py:80–99). Unchanged by this task. |
| Abuse scenarios | S1 (unbounded irreversible backups/releases under an N-capped grant), S2 (grant-free `shell` advertised read-only), T5 (empty seed list silently skips CI), T3 (silent seed-grant weakening). All closed. |

Tests (2026-11-13):
- `pytest tests/ -k tool_registry` → 592 passed, 1 skipped.
- Full aiosh-mcp suite → 138 failed, 1886 passed, 6 skipped. 136 failures are the Rust debug binary not being built on this
  host (`FileNotFoundError` / `aiosh-mcp.exe must exist`), and 1 is the known `test_runbook_config_integration` baseline failure.
  The last one, `test_largest_possible_catalog_stays_bounded`, is a 2 s wall-clock bound that read 2.86 s while another job was hashing
  8643 evidence files. Rerun alone it passed 3/3. Its load sensitivity is taken up in T-03420 (hardening).
- `tools/check_evidence.py` → PASS (E1..E4).

## PoR standing rule
S1 closes a real I-2 budget gap in strict mode. Backups and releases now count against `max_irreversible`, as they already did in
the Rust PEP. **No bypass.** No blocking note needed: no scenario remains open.
