# T-03301 Evidence: Agent Loop Hardening — MCP/API surface Documentation

- Date: 2026-11-05
- `docs/SPEC-AGENT-LOOP-HARDENING-CORE-SERVICE.md`:
  - **§3 rewritten** for the 7 async tools: annotations, schema limits, `steps_tail`, history pagination (`after_id` / `next_after_id` / `truncated`, about 1 MiB pages),
    the 15 s bound, and how tool errors differ from schema errors. Three copy-pasteable `tools/call` examples.
  - **§6** adds `LOOPMCP_ERR_TIMEOUT` and `LOOPMCP_ERR_AUDIT_READ`, and documents the T-03299 rule that oversized or deep `tool_args` are rejected, never truncated.
  - **§7** states the MCP limitations: tokens travel as arguments (truncated echo on a schema error), timeouts report uncertainty,
    `list` is server-local, and the remaining two-registry write gap (`init`).
  - **§8** links the 8 MCP evidence files. All evidence links resolve (scripted check).

## Examples verified
The three `json` blocks were **extracted from the doc** and sent unchanged as `tools/call` to a real
`python -m aiosh_mcp.server` (stdio, MCP client, fresh `AIOSH_HOME` with grant `gr_docs_mcp`):
```
aios_agent_loop_start -> {"ok": true, "state": "OBSERVE"}
aios_agent_loop_advance -> {"ok": true, "step_outcome": "ok"}
aios_agent_loop_history -> {"ok": true, "events": ["aios.agent_loop.start", "aios.agent_loop.step"], "truncated": false}
```
The §4 Python example was re-run after the T-03296..T-03300 changes:
```
ok refused ABORTED
```
