# T-03425 Evidence: Tool Registry & Taxonomy — security policy Scaffold

- Date: 2026-11-13
- Spec: [T-03424-security-policy-specification.md](T-03424-security-policy-specification.md)
- New `code/aiosh-mcp/aiosh_mcp/tool_registry_policy.py`:
  - constants `SURFACES`, `REVISION_PREFIX`, `REVISION_HEX_LEN` and `SECURITY_FIELDS`;
  - the frozen `PolicyVerdict` dataclass;
  - typed stubs `policy_revision()`, `evaluate()` and `grant_reason_suffix()`, each raising `NotImplementedError("T-03426: …")`.
- **Not wired** into `_dispatch.py` or `agent_loop_policy.py` yet. A stub on the dispatch path would raise on every call, and the
  existing fail-closed handler would then require grants everywhere in strict mode. A test pins that the stubs stay off the path until T-03426.
- New `tests/test_tool_registry_policy_scaffold.py` (6): interface and field order, immutability, stubs fail loudly, no consumer wired yet.

```
$ python -c "import aiosh_mcp.tool_registry_policy, aiosh_mcp.server"     # import ok
$ python -m pytest tests/test_tool_registry_policy_scaffold.py -q
6 passed in 0.63s
$ python -m pytest tests/ -k tool_registry -q
625 passed, 1 skipped, 1437 deselected, 1 warning in 113.55s (0:01:53)
```

## Security audit (standing rule)
- The new module has no I/O, no imports beyond the data model, and is reachable from no MCP tool or dispatch path. Its stubs cannot be triggered in production.
- PEP / audit / PoR (I-2): no state-changing path added or changed. **No bypass.**
