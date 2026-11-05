# T-03365 Evidence: Tool Registry & Taxonomy — data model Scaffold

- Date: 2026-11-06
- Spec: [T-03364-spec.md](T-03364-spec.md)
- New `code/aiosh-mcp/aiosh_mcp/tool_registry_data_model.py`:
  - `TOOLREG_ERR_*` (5 codes), the bounds, `CANONICAL_RE`, `MCP_NAME_RE` and `NETWORK_PREFIXES`
  - enums `Category` / `Effect` / `ScopeKind`
  - `ToolRegistryError(code, message)`
  - frozen `ToolEntry` with the spec's 10 fields
  - `ToolCatalog`, `unknown_profile` and `default_catalog`, all stubbed with `NotImplementedError("T-03366: ...")`
- Not wired into any caller yet. The catalog is not built at import, so the stubs cannot break server start.
  The call sites are the scaffold tests.

```
$ python -c "import aiosh_mcp.tool_registry_data_model, aiosh_mcp.server; print('import ok')"
import ok
$ python -m pytest tests/test_tool_registry_data_model_scaffold.py -q
4 passed in 0.36s
```
The scaffold tests pin the enum values (they include the TS `ToolClass` set), the field order, frozenness, `MAX_NAME_LEN ==
mcp_server_core_data_model.MAX_TOOL_NAME_LEN`, the exact error-code set, and that every stub fails loudly.
