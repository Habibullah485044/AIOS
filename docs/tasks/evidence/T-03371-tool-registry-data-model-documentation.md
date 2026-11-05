# T-03371 Evidence: Tool Registry & Taxonomy — data model Documentation

- Date: 2026-11-06
- New operator doc: [`docs/SPEC-TOOL-REGISTRY-DATA-MODEL.md`](../../SPEC-TOOL-REGISTRY-DATA-MODEL.md)
  - what shipped;
  - the taxonomy and all seven consistency rules, including "never weaker than today's name rules";
  - lookups and the fail-closed unknown profile;
  - a copy-pasteable Python example and two JSON MCP tool calls;
  - every error code;
  - coverage and drift checks;
  - known limitations;
  - evidence links for T-03363..T-03370.
- **Limitations are stated, not omitted:**
  - not enforcing yet;
  - per-name, not per-call irreversibility;
  - covers 17 of 69 served tools;
  - annotations not yet applied to served tools;
  - in-process immutability is by convention only;
  - TS/Rust do not consume the export, and Rust's reversible pentest discovery tools still differ.

## Doc drift test (`code/aiosh-mcp/tests/test_tool_registry_doc.py`, 4; part of CI suite #35)
- every `TOOLREG_ERR_*` code is documented, and the doc mentions no removed code;
- every enum value is documented, and the documented entry count matches the default catalog;
- the Python example is executed and must print exactly the `# ->` lines;
- every JSON tool call is validated against the live server's argument schema.
```
$ python -m pytest tests/test_tool_registry_doc.py -q
4 passed in 4.57s
```
