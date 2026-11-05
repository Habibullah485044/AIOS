# T-03385 Evidence: Tool Registry & Taxonomy — CLI surface Scaffold

- Date: 2026-11-06
- Spec: [T-03384-spec.md](T-03384-spec.md)
- New `code/aiosh-mcp/aiosh_mcp/tool_registry_cli.py`:
  - exit codes `0` / `1` / `2`, and `TOOLCLI_ERR_{USAGE,IO,UNAVAILABLE}`;
  - the bounds: 256 names, 256 chars per name, 80 chars shown;
  - the `CliResult` envelope;
  - a raising `_Parser`, with all five spec subcommands and their options already defined;
  - `dispatch_cli` and `main`, stubbed with `NotImplementedError("T-03386: ...")`.
- The console script entry is added together with the implementation (T-03386), so an install never exposes a stub.

```
$ python -c "import aiosh_mcp.tool_registry_cli, aiosh_mcp.server; print('import ok')"
import ok
$ python -m pytest tests/test_tool_registry_cli_scaffold.py -q
4 passed in 0.54s
```
