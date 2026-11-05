# T-03390 Evidence: Tool Registry & Taxonomy — CLI surface Hardening

- Date: 2026-11-06
- Scope: failure modes of `aiosh-tool-registry` left after the T-03389 review. The review covered pipes, encodings, terminal injection,
  missing stdout, export atomicity and stderr routing.

## Gaps found (probe) and fixed
| Failure mode | Before | After |
|---|---|---|
| **Ctrl-C** | a `KeyboardInterrupt` escaped `main()`: traceback for the operator, Python's default exit code | `TOOLCLI_ERR_INTERRUPTED: interrupted` on stderr, exit **130** (the agent-loop CLI convention), no traceback. Nothing to undo: the CLI is read-only, and `export` removes its own temp file on interrupt (tested end to end) |
| **`--help` / `-h`** | `TOOLCLI_ERR_USAGE: unrecognized arguments: --help`, exit 2 | a usage text listing every subcommand and the exit codes, exit **0**, on stdout. `--help` after `--` is still a *name* |
| **Export size** | unbounded (in practice < 1 MiB, T-03370) | defensive cap `MAX_EXPORT_BYTES = 4 MiB`: over the cap is `TOOLCLI_ERR_IO`, nothing written, no temp file |

Error envelope: every outcome is a `CliResult` with a documented code (`TOOLCLI_ERR_USAGE`, `TOOLCLI_ERR_IO`,
`TOOLCLI_ERR_UNAVAILABLE`, now `TOOLCLI_ERR_INTERRUPTED`) and exit code (`0` / `1` / `2` / `130`).
Cleanup: no DB, sockets or processes are held. The only resource is the export temp file, which is removed on error, interrupt and
`fdopen` failure (T-03389).
Retries and timeouts: none are needed, because the CLI does no network or external process I/O.

## Tests (`code/aiosh-mcp/tests/test_tool_registry_cli_hardening.py`, 8)
| Test | Old code | New code |
|---|---|---|
| Ctrl-C exits 130 without traceback | **interrupt escapes and aborts the whole pytest session** | passes |
| interrupted export leaves no temp, exit 130 | **same** | passes |
| `--help`, `-h`, `list --help`, `export -h …` → exit 0 with every subcommand | **fails** ×4 | passes |
| `check -- --help` treats it as a name | passes | passes |
| export size cap | **fails** | passes |
```
$ python -m pytest tests/ -k tool_registry -q
354 passed, 1 skipped, 1437 deselected, 1 warning in 31.55s
```
The scaffold test now pins the four error codes, `TOOLCLI_ERR_INTERRUPTED` included.
