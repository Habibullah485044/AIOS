# T-03381 Evidence: Tool Registry & Taxonomy — core service Documentation

- Date: 2026-11-06
- Updated operator doc: [`docs/SPEC-TOOL-REGISTRY-DATA-MODEL.md`](../../SPEC-TOOL-REGISTRY-DATA-MODEL.md). It gains a new **§6b Core service**,
  an updated §7, and §8 links to the T-03373..T-03380 evidence.
  - **What shipped:** `ToolRegistryService.decide` and its `ToolDecision` fields; that it is pure; the two production call sites
    (dispatch, agent-loop policy).
  - **How to invoke:**
    - a mode table for `AIOSH_TOOL_REGISTRY_MODE` (unset = shadow, `strict` in any case or width, anything else = strict, fail closed);
    - the fallback behaviour;
    - a copy-pasteable Python example;
    - the one-line command to start a server in strict mode.
  - **Errors:** `TOOLSVC_ERR_MODE`.
  - **Limitations, stated:**
    - strict tightens only the dispatch grant requirement and agent-loop irreversibility; scope is reported, not enforced;
    - about 45 MCP tools never pass through `dispatch()`;
    - the mode is fixed at first use;
    - strict will refuse some calls that pass today.

    §7's "Not enforcing yet" becomes "Advisory by default", with a pointer to §6b.

## Doc drift test (extended)
`code/aiosh-mcp/tests/test_tool_registry_doc.py` now:
- checks `TOOLREG_ERR_*` **and** `TOOLSVC_ERR_*` codes in both directions;
- runs **every** `python` block, not just the first, with `AIOSH_TOOL_REGISTRY_MODE` cleared from the environment;
- requires each block to print exactly its `# ->` lines.
```
$ python -m pytest tests/test_tool_registry_doc.py -q
5 passed in 5.73s
```
