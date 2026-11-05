# T-03388 Evidence: Tool Registry & Taxonomy — CLI surface Integration

- Date: 2026-11-06
- **Production surfaces:** console script `aiosh-tool-registry` (declared in `pyproject.toml` in T-03386) and
  `python -m aiosh_mcp.tool_registry_cli`.
  - The local editable install predates the console-script entries, so neither `aiosh-agent-loop` nor `aiosh-tool-registry` is on PATH
    here. They appear after `pip install -e code/aiosh-mcp`, which I did not run against your environment.
  - The test therefore resolves the declared entry point (`module:function`) and calls it.

## Tests (`code/aiosh-mcp/tests/test_tool_registry_cli_integration.py`, 5)
| Test | Asserts |
|---|---|
| console script entry point resolves | the `pyproject.toml` line `aiosh-tool-registry = "aiosh_mcp.tool_registry_cli:main"` imports and runs (`list --json` → 0) |
| `python -m` end to end (subprocess) | `list --json` → 0 with the full count and an empty stderr; `check` with an unregistered name → **exit 1** reaches the shell; a usage error → **exit 2**, message on stderr, **no traceback**; `export` prints exactly `export_json()` |
| CLI and MCP agree on every name | for all 140+ canonical and MCP names, plus 2 unknown ones, `dispatch_cli(["get", n]).data` equals the MCP `aios_tool_registry_get(n)` data |
| CLI never touches the audit DB | after `list` and `decide --mode strict`, `$AIOSH_HOME/audit.db` does not exist (TOOLCLI-INV1) |
| **cross-substrate:** exported catalog read by TS | `export --out` → node reads the canonical JSON (`schema_version` 1, all entries); TS `isIrreversible` is never stricter than the catalog (the catalog may be stricter by design); TS `toolGlobMatch` equals Python `tool_glob_match` for each canonical name under its family glob |

```
$ python -m pytest tests/test_tool_registry_cli_integration.py -q
5 passed in 7.69s
```
The closest existing suites are CI #35 `tool_registry` (runs these via `-k tool_registry`) and the agent-loop battery (ship gate).
Both pass in the ship gate.
