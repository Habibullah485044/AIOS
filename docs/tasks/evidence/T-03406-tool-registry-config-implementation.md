# T-03406 Evidence: Tool Registry & Taxonomy — configuration Implementation

- Date: 2026-11-06
- Spec: [T-03404-spec.md](T-03404-spec.md). Module: `code/aiosh-mcp/aiosh_mcp/tool_registry_config.py`.

## What was implemented
- **`resolve(arg_mode, overrides)`.** Never raises; writes nothing; audits nothing.
  - **Numbers:** argument → env → file → default, then clamped. Clamping is reported as `TOOLREGCONF_ERR_BOUNDS` and still applied. A non-integer
    env value is ignored for that key (`TOOLREGCONF_ERR_ENV`).
  - **Mode: strictest wins** over argument, env and file. NFKC, trimmed and case-insensitive. Any unrecognised non-empty value is strict; empty
    or absent is no opinion. `sources["mode"]` names every source that asked for strict.
  - **File:** `AIOSH_TOOL_REGISTRY_CONFIG`, else `docs/tool_registry_config.json`.
    - It reuses the agent-loop config's hardened checks (path hygiene; no UNC or device paths; regular files only, re-checked after
      open; non-blocking open; 64 KiB cap read as cap+1 bytes).
    - Any defect (locked key, unknown key, wrong type, not an object, bad JSON, oversize, IO) **ignores the whole file**, with a named code.
- **`process_config()` / `reset_process_config()`:** once per process, lock-protected.
- **Wiring:**
  - `ToolRegistryService` reads mode and `unregistered_samples` at construction (a fresh `resolve()`). `intended_mode()` (the
    hooks' fail-closed fallback) uses the combined, strictest mode.
  - `report()` caps lines at `report_max_lines`.
  - `aios_tool_registry_stats` adds `config` (values and sources) and `config_errors`.
- Defaults equal the previous constants (pinned by the scaffold test), so with no env and no file **behaviour is unchanged**.

## Tests (`code/aiosh-mcp/tests/test_tool_registry_config_impl.py`, 25)
- Defaults; precedence argument > env > file > default.
- **9 strictest-wins mode cases** (a file cannot downgrade an env strict and vice versa; typos are strict; empty is shadow).
- 8 whole-file rejections: 2 locked keys, unknown key, string number, bool number, non-string mode, array, bad JSON.
- Clamping both ways; bad env number; oversize file; `..` path; `CON`; a directory; the default file picked up; the service honouring
  mode and sample cap; resolving writes nothing.
```
$ python -m pytest tests/ -k tool_registry -q
450 passed, 1 skipped, 1437 deselected, 1 warning in 38.83s
```
