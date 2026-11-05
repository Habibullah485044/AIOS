# T-03386 Evidence: Tool Registry & Taxonomy — CLI surface Implementation

- Date: 2026-11-06
- Spec: [T-03384-spec.md](T-03384-spec.md). Module: `code/aiosh-mcp/aiosh_mcp/tool_registry_cli.py`. Console script
  `aiosh-tool-registry` was added to `pyproject.toml`; `python -m aiosh_mcp.tool_registry_cli` also works.
- Tests were written first: `tests/test_tool_registry_cli_impl.py` (17).

## What was implemented
- **`dispatch_cli(argv) -> CliResult`.** It never raises. It covers:
  - NUL bytes, more than 256 names, names over 256 chars, unknown subcommands, options or modes, and argparse errors → exit 2 /
    `TOOLCLI_ERR_USAGE`;
  - a catalog build failure → exit 1 / `TOOLCLI_ERR_UNAVAILABLE`.
- **`list [--category]`**, **`get <name>`** (exit 1 with the fail-closed profile if unregistered), **`decide`** (the service's `ToolDecision`,
  `--target`, `--require-grant`, `--mode`), and **`check <names…>`** (exit 1 if any is unregistered).
- **`export [--out FILE]`:** stdout gets exactly `export_json()`. `--out` writes **atomically** (temp file in the target directory, fsync,
  `os.replace`), refuses non-regular targets (directories, symlinks, devices), removes the temp file on failure, and reports path, bytes
  and sha256.
- **`main`:** `--json` gives a sorted, ASCII envelope. Human output strips control and bidi characters and cuts names to 80 chars. Usage errors go
  to stderr. A closed stdout pipe exits 0 quietly.
- Read-only (TOOLCLI-INV1): no DB, no audit rows, no network; the only write is `export --out`.

## Results
```
$ python -m pytest tests/ -k tool_registry -q
308 passed, 1437 deselected, 1 warning in 22.32s

$ python -m aiosh_mcp.tool_registry_cli check aios.fs.read pentest.nmap nope.tool ; echo exit=$?
ok   aios.fs.read -> aios.fs.read  (grant)
ok   pentest.nmap -> pentest.nmap  (grant)
MISSING nope.tool -> nope.tool  (grant)
exit=1
$ python -m aiosh_mcp.tool_registry_cli list | head -1 ; echo pipe exit=${PIPESTATUS[0]}
aios.agent_loop.abort                agent_loop     destructive -            none
pipe exit=0
$ python -m aiosh_mcp.tool_registry_cli get 'x$(id)'          # malformed name: fail-closed profile, not echoed
unregistered.0f35e4cec34e3830: NOT REGISTERED (fail-closed profile)
...
```
