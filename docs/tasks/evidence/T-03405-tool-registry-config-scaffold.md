# T-03405 Evidence: Tool Registry & Taxonomy — configuration Scaffold

- Date: 2026-11-06
- Spec: [T-03404-spec.md](T-03404-spec.md)
- New `code/aiosh-mcp/aiosh_mcp/tool_registry_config.py`:
  - the 7 `TOOLREGCONF_ERR_*` codes;
  - env names, the default file path, the 64 KiB cap and the path-length bound;
  - `MODES`;
  - `FIELDS` (`report_max_lines` 32 in 0..1000, `unregistered_samples` 50 in 0..200, each with its env name);
  - the 7 `LOCKED_KEYS`;
  - `resolve` / `process_config` / `reset_process_config`, stubbed with `NotImplementedError("T-03406: ...")`.
- Not wired into the service yet (T-03406).
- The scaffold test pins the defaults to the service's current constants, so wiring cannot silently change behaviour.

```
$ python -c "import aiosh_mcp.tool_registry_config, aiosh_mcp.server; print('import ok')"
import ok
$ python -m pytest tests/test_tool_registry_config_scaffold.py -q
4 passed
```
