# T-03401 Evidence: Tool Registry & Taxonomy — API surface Documentation

- Date: 2026-11-06
- Updated operator doc: [`docs/SPEC-TOOL-REGISTRY-DATA-MODEL.md`](../../SPEC-TOOL-REGISTRY-DATA-MODEL.md). It gains **§6d MCP API** and §8 links to
  the T-03393..T-03400 evidence.
  - **What shipped:** `aios_tool_registry_decide` (own counters) and `aios_tool_registry_stats` (server counters), with copy-pasteable
    JSON tool calls.
  - **The full annotation policy:** the read-only conjunction (catalog, category, scope, no grant/token/path argument, no contrary existing
    claim), the never-relax rules for the other hints, the equivalence rule, the failure behaviour, and the live result (71 annotated, 35 read-only).
  - **Limitations, stated:**
    - annotations are client hints only;
    - follow-ups for path confinement in three tools and bounded segment scans, which stay non-read-only until then;
    - TS and Rust manifests are not annotated.

## Doc drift test (extended)
`code/aiosh-mcp/tests/test_tool_registry_doc.py` now also:
- validates the two new JSON tool calls against the live server schema (existing JSON check);
- asserts every `READ_ONLY_HINT_CATEGORIES` value and every grant/token parameter name appears in the doc;
- asserts the documented counts ("all **71** tools are annotated", "**35** are advertised read-only") equal the live server's.
```
$ python -m pytest tests/test_tool_registry_doc.py -q
13 passed in 9.60s
```
