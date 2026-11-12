# T-03421 Evidence: Tool Registry & Taxonomy — automated tests Documentation

- Date: 2026-11-13
- Updated operator doc: [`docs/SPEC-TOOL-REGISTRY-DATA-MODEL.md`](../../SPEC-TOOL-REGISTRY-DATA-MODEL.md). It gains **§6f Automated tests**,
  and §8 links the T-03413..T-03421 evidence.
  - What runs, where, and that CI suite #35 (`-k tool_registry`) picks it up.
  - Three copy-pasteable commands: the whole battery, the properties only, and a widened or replayed run with knobs. The PowerShell form is given too.
  - Properties P1–P6, one line each, stated as what holds for every generated case.
  - The knob table (default and bounds), and that a bad knob is an error naming the variable, never a skip. How a failure replays from its seed.
  - The guards next to the properties: seed lock, Rust drift (its known lists), and the watchdog (soft `TimeoutError`, hard kill 30 s later).
- **Limitations, stated:**
  - the oracles share the doc's mistakes;
  - fixed default seeds;
  - Rust is compared by source, and TS parity needs `node` plus a built dist;
  - the hard-stage stack dump can be lost under capture;
  - the watchdog covers only the property module.

## Doc drift test (extended)
`test_tool_registry_doc.py::test_documented_automated_tests_match_the_helpers` checks:
- the three knob rows against `tool_registry_model` (defaults, `MAX_SEEDS`, `MAX_CASES`, `DEFAULT_TIMEOUT_S`, `MAX_TIMEOUT_S`);
- the defaults as the helpers really apply them, with the env cleared;
- the stated hard-kill grace against `HARD_KILL_GRACE_S`;
- that every `test_tool_registry_*.py` file the section names exists;
- that the documented drift lists equal `RUST_WEAKER` / `CATALOG_WEAKER`;
- that every property P1–P6 has a row.

## Commands run as documented (from `code/aiosh-mcp`)
```
$ python -m pytest tests/ -k tool_registry -q
619 passed, 1 skipped, 1437 deselected, 1 warning in 88.73s (0:01:28)
$ AIOSH_TOOLREG_FUZZ_SEEDS=7 AIOSH_TOOLREG_FUZZ_N=2000 python -m pytest tests/test_tool_registry_properties.py -q
6 passed in 8.95s
$ python -m pytest tests/test_tool_registry_doc.py -q
15 passed in 12.78s
```
Wording checked against the code. §7 says Rust treats "four pentest discovery tools" as reversible. The parser confirms it:
`pentest.arp.scan`, `pentest.network.interfaces`, `pentest.tshark` and `pentest.wifi.scan`. Only `pentest.tshark` is a catalog
entry, so §6f says its drift list covers catalog entries.

## Security audit (standing rule for every shipped task)
- Docs and one read-only doc test. No production code, config or policy changed.
- The documented commands run only the test suite. No credentials, hosts or paths that would leak are shown.
- The doc tells operators that changing a catalog security field must change the seed lock in the same PR. This keeps that
  review gate visible.
- PEP / audit / PoR (I-2): no state-changing path touched. **No bypass.**
