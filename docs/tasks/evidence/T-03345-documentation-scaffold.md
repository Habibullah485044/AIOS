# T-03345 Evidence: Agent Loop Hardening — documentation Scaffold

- Date: 2026-11-05
- New `code/aiosh-mcp/aiosh_mcp/agent_loop_doc.py`:
  - `SECTIONS`
  - `ERROR_MEANINGS`: one line for **all 34** `*_ERR_*` codes. This is the only hand-written table; it includes the 17 the spec doc is missing.
  - stub `reference()` that raises `NotImplementedError("T-03346: ...")`
- `tests/test_agent_loop_doc_scaffold.py`: `ERROR_MEANINGS` keys equal the set of `*_ERR_*` constants defined in `aiosh_mcp/agent_loop_*.py`, **in both directions**.
  So a new code without a meaning, or a meaning for a removed code, fails CI. The stub fails loudly.

```
$ python -c "import aiosh_mcp.agent_loop_doc, aiosh_mcp.server; print('import ok')"
import ok
2 passed in 0.33s
```
