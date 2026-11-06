# T-03395 Evidence: Tool Registry & Taxonomy — API surface Scaffold

- Date: 2026-11-06
- Spec: [T-03394-spec.md](T-03394-spec.md)
- New `code/aiosh-mcp/aiosh_mcp/tool_registry_api.py`:
  - the tool names `aios_tool_registry_decide` / `aios_tool_registry_stats`;
  - `READ_ONLY_HINT_CATEGORIES`;
  - `more_cautious`, `apply_catalog_annotations` and `register_tool_registry_api_tools`, stubbed with `NotImplementedError("T-03396: ...")`.
- Not wired into `server.py` yet (T-03396), so the stubs cannot affect server start.

```
$ python -c "import aiosh_mcp.tool_registry_api, aiosh_mcp.server; print('import ok')"
import ok
$ python -m pytest tests/test_tool_registry_api_scaffold.py -q
2 passed
```
