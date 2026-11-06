# T-03391 Evidence: Tool Registry & Taxonomy — CLI surface Documentation

- Date: 2026-11-06
- Updated operator doc: [`docs/SPEC-TOOL-REGISTRY-DATA-MODEL.md`](../../SPEC-TOOL-REGISTRY-DATA-MODEL.md). It gains **§6c Operator CLI** and
  §8 links to the T-03383..T-03390 evidence.
  - **How to invoke:** `python -m aiosh_mcp.tool_registry_cli`, and the console script after `pip install -e code/aiosh-mcp`. Six
    copy-pasteable commands are each annotated with their exit code.
  - **Reference:** a subcommand table, the `--json` envelope, exit codes `0`/`1`/`2`/`130`, the output-safety guarantees (ASCII-escaped,
    errors on stderr, quiet closed pipe), and all four `TOOLCLI_ERR_*` codes.
  - **Limitations, stated:**
    - `export --out` replaces the file (Windows ACLs not kept; POSIX mode kept);
    - no `stats` from the CLI;
    - no TS command yet.

## Doc drift test (extended; part of CI suite #35)
`code/aiosh-mcp/tests/test_tool_registry_doc.py` now also:
- checks `TOOLCLI_ERR_*` in both directions, alongside `TOOLREG_ERR_*` / `TOOLSVC_ERR_*`;
- **runs every documented `python -m aiosh_mcp.tool_registry_cli …` line** and asserts the exit code stated in its comment, with no traceback;
- asserts every CLI subcommand appears in a documented command.
```
$ python -m pytest tests/test_tool_registry_doc.py -q
12 passed in 9.65s
```
