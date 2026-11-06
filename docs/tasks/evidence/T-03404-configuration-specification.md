# T-03404 Specification: Tool Registry & Taxonomy — configuration

- Date: 2026-11-06
- Inputs: [T-03403-research.md](T-03403-research.md). D1–D6 are adopted.
- New module (AIOS-specific): `code/aiosh-mcp/aiosh_mcp/tool_registry_config.py`. Error prefix `TOOLREGCONF_ERR_*`; invariants
  `TOOLREGCONF-INV1..INV4`.

## 1. Keys
| Key | Type | Default | Bounds | Env |
|---|---|---|---|---|
| `mode` | `shadow` \| `strict` | `shadow` | — | `AIOSH_TOOL_REGISTRY_MODE` (existing) |
| `report_max_lines` | int | 32 | 0..1000 | `AIOSH_TOOL_REGISTRY_REPORT_MAX_LINES` |
| `unregistered_samples` | int | 50 | 0..200 | `AIOSH_TOOL_REGISTRY_UNREGISTERED_SAMPLES` |

**Locked keys** (not representable): `catalog`, `entries`, `read_only_hint_categories`, `grant_params`, `path_params`,
`irreversible_names`, `irreversible_prefixes`.

## 2. Sources and precedence
- **Config file:** the path in `AIOSH_TOOL_REGISTRY_CONFIG`, else `docs/tool_registry_config.json` if it exists. The file must be a JSON object, at most
  64 KiB, a regular file, and pass path hygiene (≤ 1024 chars, no `..`, no Windows device name).
- **Numbers:** argument → env → file → default, then clamped to bounds. Clamping is reported as `TOOLREGCONF_ERR_BOUNDS` and applied.
- **Mode:** strictest wins (TOOLREGCONF-INV1). If the argument, the env or the file says `strict` (after NFKC, trim and lower-casing), or
  says anything unrecognised and non-empty, the mode is `strict`. Otherwise it is `shadow`.

## 3. API
- `resolve(arg_mode=None, overrides=None) -> {"config": {...}, "sources": {key: source}, "errors": [str], "path": str | None}`. Never raises.
- `process_config()`: resolved once per process; `reset_process_config()` for tests.
- The service reads `report_max_lines`, `unregistered_samples` and `mode` from `process_config()` when it is built. `aios_tool_registry_stats`
  adds `config` (values and sources) and `config_errors`.

## 4. Errors
| Code | When |
|---|---|
| `TOOLREGCONF_ERR_IO` | the file is unreadable or missing (env path only), not a regular file, or fails path hygiene |
| `TOOLREGCONF_ERR_FILE_SIZE` | the file is over 64 KiB |
| `TOOLREGCONF_ERR_PARSE` | not a JSON object, or a value of the wrong type |
| `TOOLREGCONF_ERR_UNKNOWN_KEY` | a key that is not in §1 |
| `TOOLREGCONF_ERR_LOCKED` | a locked key |
| `TOOLREGCONF_ERR_BOUNDS` | a number out of bounds (clamped, reported) |
| `TOOLREGCONF_ERR_ENV` | an env value is not an integer |

Any file error except `BOUNDS` ignores **the whole file** (defaults and env still apply). An env error ignores that one key.

## 5. Invariants
- **TOOLREGCONF-INV1:** configuration can never lower the mode below what any source asks for.
- **TOOLREGCONF-INV2:** security policy (§1 locked keys) is not configurable by any channel.
- **TOOLREGCONF-INV3:** resolving never raises, never writes files, and never writes audit rows.
- **TOOLREGCONF-INV4:** every value in use is within its bounds, and its source is reported.
