# T-03383 Research: Tool Registry & Taxonomy — CLI surface

- Date: 2026-11-06
- Question: what operator CLI should the tool registry have, and which existing conventions must it follow?
- Method: read the existing Python operator CLI (`aiosh_mcp/agent_loop_cli.py`), its packaging (`pyproject.toml`), and the TS
  `aiosh` CLI (`code/aiosh-cli/src/cli.ts`). **No code was changed.**

## A. Facts
### A1. The Python operator CLI convention (agent loop, T-03283..T-03292)
- Entry point `aiosh-agent-loop = "aiosh_mcp.agent_loop_cli:main"` (`pyproject.toml:12-14`); also `python -m aiosh_mcp.agent_loop_cli`.
- **Exit codes** (`agent_loop_cli.py:40-45`): `0` success, `1` failure, `2` usage, `3` unauthorized, `4` timeout, `130` interrupted.
- `dispatch_cli(argv, ...) -> CliResult(exit_code, subcommand, data, error_code, error)` is a pure, testable core. `main()` only
  prints: `--json` gives a machine-readable envelope, otherwise human text.
- **Hardening already established there and expected of any new CLI:**
  - NUL bytes in arguments rejected;
  - argparse errors mapped to exit 2, never a traceback;
  - a closed stdout pipe (`| head`) handled (#401);
  - secrets masked in output;
  - bounded inputs;
  - read paths open the DB read-only.
- Error codes are module constants (`LOOPCLI_ERR_*`), and the generated reference documents them in both directions (T-03345).

### A2. TS `aiosh` CLI
- `commander` subcommands: `status`, `run`, `agent`, `audit {tail,verify,rotate,segments,seen}`, `anchor`, `restraint`,
  `grant {create,list,revoke}`, `pentest {…}`, `classify <tool>` (`cli.ts:165-931`).
- **No tool-catalog command exists.** `aiosh classify <tool>` runs the constitution classifier, which is different from the taxonomy.
- The TS side does not read the Python catalog. The research for the data model (T-03363 D3) proposed `export_json()` for other
  substrates.

### A3. What the registry offers a CLI today
- Data model: `default_catalog()` with `entries()`, `resolve()`, `profile()`, `export_json()` (deterministic JSON, `schema_version: 1`).
- Service: `ToolRegistryService.decide()` and `stats()`. `stats()` is per-process, so a one-shot CLI process would only see its own decisions.
- MCP: `aios_tool_registry_list` / `aios_tool_registry_get` (read-only).

## B. Assumptions (not verified)
- Operators want this CLI mainly for three things: inspecting what a tool name means, exporting the catalog for TS/Rust or review, and
  checking a candidate name before writing a grant.
- A shell-friendly `check` that exits non-zero for unregistered or grant-required names is useful in scripts and CI.

## C. Decisions needed
| # | Decision | Recommendation |
|---|---|---|
| D1 | Entry point | `aiosh-tool-registry = "aiosh_mcp.tool_registry_cli:main"` plus `python -m aiosh_mcp.tool_registry_cli`, mirroring A1. |
| D2 | Subcommands | `list [--category C] [--json]`, `get <name> [--json]`, `decide <name> [--target T] [--require-grant] [--mode shadow\|strict] [--json]`, `export [--out FILE]`, `check <name>...`. All read-only. **No subcommand mutates the catalog** (TOOLREG-INV5). |
| D3 | `check` exit codes | `0` all registered; `1` at least one unregistered; `2` usage. Grant-required names are not failures, they are reported. |
| D4 | `export --out` | Writes atomically (temp file + rename), refuses an existing directory, and caps output at 1 MiB (already bounded by the catalog bound). Default target is stdout. |
| D5 | Stats | Not exposed: a one-shot process has none of the server's counters. Belongs to the observability epic, through the server. |
| D6 | Error codes | `TOOLCLI_ERR_USAGE`, `TOOLCLI_ERR_IO` (export write failure), and `TOOLCLI_ERR_UNAVAILABLE` (catalog failed to build). |
