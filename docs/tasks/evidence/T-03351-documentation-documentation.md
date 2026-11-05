# T-03351 Evidence: Agent Loop Hardening — documentation Documentation

- Date: 2026-11-05
- `docs/SPEC-AGENT-LOOP-HARDENING-CORE-SERVICE.md`, new **§5c Generated reference and doc drift checks**: what `aios_agent_loop_doc` / `agent_loop_cli doc`
  return; caching and safety properties; a copy-pasteable example with real output; what the CI drift test enforces, and the two-way `ERROR_MEANINGS` check.
  §8 links the 7 documentation-epic evidence files (all resolve).

## Example verified
The output of `python -m aiosh_mcp.agent_loop_cli doc --section config` (first 4 lines) was pasted verbatim from a real run.

## The doc passes its own drift test after this edit
`tests/test_agent_loop_doc_drift.py`: 10 passed. Every identifier is documented, the `python` blocks run, and the `json` blocks validate.

## Limitations stated (in §5c and earlier sections)
The drift check matches identifiers textually; it cannot judge whether prose *explanations* are still accurate. The generated reference is the
authoritative source for agents.
