# T-03384 Specification: Tool Registry & Taxonomy — CLI surface

- Date: 2026-11-06
- Inputs: [T-03383-research.md](T-03383-research.md). Decisions D1–D6 are adopted.
- New module (AIOS-specific): `code/aiosh-mcp/aiosh_mcp/tool_registry_cli.py`. Console script `aiosh-tool-registry`, and
  `python -m aiosh_mcp.tool_registry_cli`.
- Error prefix `TOOLCLI_ERR_*`; invariants `TOOLCLI-INV1..INV4`.

## 1. Contract
`dispatch_cli(argv: list[str], stdout_is_tty: bool = False) -> CliResult(exit_code, subcommand, data, error_code, error)` is pure and
testable. `main(argv=None) -> int` prints the result (`--json` → `{"ok", "subcommand", "data", "error_code", "error"}`; otherwise
human-readable lines) and returns the exit code.

| Subcommand | Arguments | Output `data` | Exit |
|---|---|---|---|
| `list` | `[--category C]` (choices = `Category` values) | `{"count", "entries": [entry…]}` | 0 |
| `get` | `<name>` (canonical or MCP name) | `{"registered": bool, "entry": entry}`; an unregistered name gives the fail-closed profile | 0 if registered, **1** if not |
| `decide` | `<name> [--target T] [--require-grant] [--mode shadow\|strict]` | the `ToolDecision` as a dict (scope kinds as strings) | 0 |
| `export` | `[--out FILE]` | stdout: exactly `catalog.export_json()`. With `--out`: `{"path", "bytes", "sha256"}` | 0, or 1 on I/O error |
| `check` | `<name>...` (1..256 names) | `{"names": [{"name", "registered", "canonical", "requires_grant", "irreversible"}…], "unregistered": n}` | 0 if all registered, **1** otherwise |

Common options: `--json`. Exit codes follow the agent-loop CLI (`0` success, `1` failure / negative result, `2` usage).

## 2. Invariants
- **TOOLCLI-INV1 (read-only):** no subcommand changes the catalog. Only `export --out` writes, and only that one file. There is no DB
  access, no audit row, and no network access.
- **TOOLCLI-INV2 (fail closed, never crash):**
  - Any argv gives a `CliResult`, never a traceback.
  - NUL bytes in arguments, more than 256 names, and names longer than 256 characters are usage errors (exit 2).
  - Unknown names get the fail-closed profile.
- **TOOLCLI-INV3 (safe output):**
  - Names shown in human output have control and bidi characters stripped and are cut to 80 characters.
  - JSON output uses `ensure_ascii`.
  - A closed stdout pipe (`| head`) exits quietly with 0.
- **TOOLCLI-INV4 (atomic export):**
  - `--out` writes to a temp file in the target directory and renames it into place.
  - It refuses a target that is a directory, a symlink or a special file (`TOOLCLI_ERR_IO`, exit 1).
  - A failed write leaves no partial file and no temp file.

## 3. Errors
| Code | When |
|---|---|
| `TOOLCLI_ERR_USAGE` | bad arguments: argparse error, NUL byte, too many or too long names, unknown mode (exit 2) |
| `TOOLCLI_ERR_IO` | `export --out` cannot write, or the target is a directory, symlink or special file (exit 1) |
| `TOOLCLI_ERR_UNAVAILABLE` | the catalog failed to build (exit 1) |

## 4. Audit and persistence effects
None, apart from the `export --out` file.

## 5. Out of scope
Server-side counters (observability epic), any mutation, and a TS `aiosh tools` command (cross-substrate epic).
