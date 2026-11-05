# T-03348 Evidence: Agent Loop Hardening — documentation Integration

- Date: 2026-11-05

## Production surfaces
| Surface | Change |
|---|---|
| MCP | New **`aios_agent_loop_doc(section?)`** (`readOnlyHint`). `section` is a schema enum of `tools/errors/config/cli/policy`; anything else is an MCP tool error. It returns the code-generated reference. Catalog: 64 -> **65**; `TOOL_ANNOTATIONS` covers 10. |
| CLI | New **`python -m aiosh_mcp.agent_loop_cli doc [--section S] [--json]`**. The human view is a table per section; a bad section exits 2. |

## Gap found by the integration test and fixed
The reference listed only the 10 service tools and **omitted the 2 legacy data-model tools** (`aios_agent_loop_init`, `aios_agent_loop_status`), which the
server also serves. `reference("tools")` now registers both sets, so it matches the server's complete `aios_agent_loop_*` catalog (asserted over real stdio).

## Integration smoke (real stdio server)
`tests/test_agent_loop_doc_integration.py`: the tool is read-only and its `section` enum is published; the errors section has 34 codes; the tools section equals the server's
`aios_agent_loop_*` tool set; a bad section is `isError`; **parity:** CLI `doc --section errors --json` == MCP result.
```
16 passed in 6.63s   (doc integration + impl + drift)
```
