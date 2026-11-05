# T-03387 Evidence: Tool Registry & Taxonomy — CLI surface Unit Test

- Date: 2026-11-06
- New `code/aiosh-mcp/tests/test_tool_registry_cli_unit.py` (16 tests), standalone.

## Coverage
| Area | Cases |
|---|---|
| Boundaries | 256 names accepted, 257 refused (exit 2); a 256-char name accepted, 257 refused; every `Category` filter, with counts summing to the catalog size |
| Hostile input | odd argv (`None`, ints, bytes, options with no subcommand, extra arguments) never raises; ANSI escape, bidi override and newline-plus-fake-line in a name are not echoed raw; `--json` output is ASCII and parseable for non-ASCII names; usage errors go to stderr, not stdout |
| Export (TOOLCLI-INV4) | a regular file is overwritten atomically; a missing parent directory gives `TOOLCLI_ERR_IO` and nothing is created; a **symlink target is refused** and its target left intact; a failed rename (ENOSPC) leaves **no temp file**; a catalog build failure gives `TOOLCLI_ERR_UNAVAILABLE` |
| Closed pipe | a stdout that raises `BrokenPipeError` on write and flush exits 0 |

## Results
```
$ python -m pytest tests/test_tool_registry_cli_unit.py -q
15 passed, 1 skipped in 1.03s
```
The skip is the symlink test: this Windows account may not create symlinks (no Developer Mode or privilege). It runs where symlinks are
permitted, e.g. on Linux CI.

## Mutations (applied one at a time, then reverted)
| Mutation | Result |
|---|---|
| M1: the temp file is not removed on a failed write | 1 failed |
| M2: `check` shows raw names (no `_shown`) | 1 failed |
| M3: no bound on the number of names | 1 failed |
