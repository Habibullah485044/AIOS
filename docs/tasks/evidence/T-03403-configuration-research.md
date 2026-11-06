# T-03403 Research: Tool Registry & Taxonomy — configuration

- Date: 2026-11-06
- Question: what about the tool registry should operators be able to configure, through which channels, and what must stay locked?
- Method: read the existing configuration subsystem (`aiosh_mcp/agent_loop_config.py`, T-03303..T-03312) and every place the registry
  reads settings today. **No code was changed.**

## A. Facts
### A1. The established pattern (`agent_loop_config.py`)
- **Precedence:** argument → per-field env → config file → default, then clamp to bounds (module docstring, lines 9-11).
- **Config file:** `AIOSH_AGENT_LOOP_CONFIG` (env path) or `docs/agent_loop_config.json` (default), with:
  - a hard cap of 64 KiB (`MAX_CONFIG_FILE_BYTES`, :27);
  - path hygiene: ≤ 1024 chars, no `..`, Windows device names refused (`_WIN_DEVICE`, :48, `hygiene_ok`, :105);
  - read with `os.read` of at most cap+1 bytes (:193).
- **Errors** are named codes (`AGENTLOOPCONF_ERR_{FILE_SIZE,IO,PARSE,UNKNOWN_KEY,LOCKED,BOUNDS,ENV}`, :34-40). A bad file is **ignored
  whole** (defaults apply) and reported, never fatal.
- **Locked keys** (`LOCKED_KEYS`, :79): security and audit controls cannot be set by configuration at all (AGENTLOOPCONF-INV2).
- `process_config()` (:295) resolves once per process, and `reset_process_config()` (:307) exists for tests. A degraded config writes one
  honest audit row (`audit_degraded`, :313).

### A2. What the registry reads today
- `AIOSH_TOOL_REGISTRY_MODE` (`tool_registry_service.py:96`): `shadow` (default) or `strict`. An unrecognised value means strict (T-03379).
  This is the only external setting.
- Hard-coded tunables:
  - `MAX_REPORT_LINES = 32` and `MAX_UNREGISTERED_SAMPLES = 50` (service);
  - `MAX_EXPORT_BYTES = 4 MiB` (CLI);
  - `MAX_QUERY_LEN = 256` (MCP).
- Security policy constants that must never be configurable:
  - the catalog itself (TOOLREG-INV5);
  - `READ_ONLY_HINT_CATEGORIES`, `GRANT_PARAMS`, `PATH_PARAMS` (TOOLAPI-INV2);
  - `IRREVERSIBLE_NAME_PREFIXES` / `IRREVERSIBLE_NAMES` (the never-weaker floor, T-03369).

## B. Assumptions (not verified)
- Operators want the mode in a file as well as in the env (service managers, containers), and want to tune the log noise.
- Nobody needs to change the catalog at runtime. Proposals go through PRs (TOOLREG-INV5), and none are planned.

## C. Decisions needed
| # | Decision | Recommendation |
|---|---|---|
| D1 | Module | A new `tool_registry_config.py` following A1: env path `AIOSH_TOOL_REGISTRY_CONFIG`, default file `docs/tool_registry_config.json`, 64 KiB cap, the same hygiene, and its own `TOOLREGCONF_ERR_*` codes. |
| D2 | Tunable keys | `mode` (`shadow`/`strict`), `report_max_lines` (0..1000, default 32), `unregistered_samples` (0..200, default 50). Nothing else. |
| D3 | Mode precedence | **Strictest wins, not first wins.** If any source (argument, env, file) says `strict`, the mode is strict. A file cannot downgrade an env `strict` to shadow, and vice versa. An unrecognised value in any source counts as strict (as T-03379 does for the env). |
| D4 | Locked keys | `catalog`, `entries`, `read_only_hint_categories`, `grant_params`, `path_params`, `irreversible_names`, `irreversible_prefixes`. Any of them in a file → `TOOLREGCONF_ERR_LOCKED`, and the whole file is ignored. |
| D5 | Failure behaviour | Like A1: a bad file is ignored whole and reported (stderr plus a `config_errors` list in `aios_tool_registry_stats`), never fatal. **Unlike A1, no audit row**: the registry writes none (TOOLSVC-INV3). |
| D6 | When it applies | Resolved once at the first `service()` build, like the mode today (fixed at first use). |
