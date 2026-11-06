# T-03418 Evidence: Tool Registry & Taxonomy — automated tests Integration

- Date: 2026-11-06
- The property suite now reaches the **production surfaces** and the **other substrates**. All of it runs in CI suite #35 (`-k tool_registry`).

## Tests
| File | Asserts |
|---|---|
| `tests/test_tool_registry_properties_integration.py` (3 seeds) | Generated names (registered, upper case, separator swaps, fullwidth, risky prefixes, bidi) are sent through the **real server's** `aios_tool_registry_decide` and the **CLI core** (`aiosh-tool-registry decide`). Both must equal the service's own decision field by field, and stay above the never-weaker floor. Names the published schema or CLI rejects (non-str, empty, > 256 chars, NUL) are skipped. |
| `tests/test_tool_registry_rust_drift.py` (2) | Parses Rust `pep::is_irreversible` from `aiosh-core/src/pep.rs` (the binary is not built here), checks the parser sees the rule, then compares the result for every catalog entry. **Any new difference fails**, so drift cannot grow silently. |

## Rust drift found (pinned, not hidden)
| Direction | Names | Note |
|---|---|---|
| Rust weaker than the catalog | `pentest.tshark` | Known since the research (T-03363 B4.4): Rust treats offline/discovery pentest tools as reversible. |
| **Catalog weaker than Rust** | `aios.backup.create`, `aios.release.generate` | **New.** Rust counts them irreversible; the catalog marks them grant-required (`_dispatch(require_grant=True)`) but not irreversible. This is handed to the security review (T-03419) to decide which side is right. |

## Results
```
$ python -m pytest tests/test_tool_registry_rust_drift.py tests/test_tool_registry_properties_integration.py -q
5 passed in 8.88s
rust weaker: ['pentest.tshark']; catalog weaker: ['aios.backup.create', 'aios.release.generate']
```
