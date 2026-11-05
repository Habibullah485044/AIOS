# T-03375 Evidence: Tool Registry & Taxonomy — core service Scaffold

- Date: 2026-11-06
- Spec: [T-03374-spec.md](T-03374-spec.md)
- New `code/aiosh-mcp/aiosh_mcp/tool_registry_service.py`:
  - `TOOLSVC_ERR_MODE`, `ENV_MODE`, `MODES` (`shadow` default, `strict`), `DISAGREEMENT_KINDS`, the sample bound and the log event name;
  - `ToolServiceError`;
  - frozen `ToolDecision` with the spec's 7 fields;
  - `ToolRegistryService` (`decide` / `enforcement` / `stats`) and `service()`, all stubbed with `NotImplementedError("T-03376: ...")`.
- No caller is wired yet (that is the integration task), so the stubs cannot affect any production path.

```
$ python -c "import aiosh_mcp.tool_registry_service, aiosh_mcp.server; print('import ok')"
import ok
$ python -m pytest tests/test_tool_registry_service_scaffold.py -q
4 passed in 0.55s
```
