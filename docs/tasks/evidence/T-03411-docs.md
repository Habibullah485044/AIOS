# T-03411 Evidence: Tool Registry & Taxonomy — configuration Documentation

- Date: 2026-11-06
- Updated operator doc: [`docs/SPEC-TOOL-REGISTRY-DATA-MODEL.md`](../../SPEC-TOOL-REGISTRY-DATA-MODEL.md). It gains **§6e Configuration** and
  §8 links to the T-03403..T-03410 evidence.
  - A key table (defaults, bounds, env names).
  - File rules: env path, else `$AIOSH_HOME`; 64 KiB; BOM ok; no duplicate keys; refused path forms.
  - A copy-pasteable example file.
  - Precedence: numbers in order; strictest-wins mode; an unusable config counts as strict.
  - The locked keys, and where to see problems (stderr once; stats codes).
  - All seven `TOOLREGCONF_ERR_*` codes.
- **Limitations, stated:** no reload (next start); `unregistered_samples=0` allowed; config-file ACLs are not checked.

## Doc drift test (extended)
`code/aiosh-mcp/tests/test_tool_registry_doc.py`:
- `TOOLREGCONF_ERR_*` codes are checked in both directions;
- every key's table row (default, bounds, env) must match `FIELDS` exactly;
- every locked key must appear;
- **the documented example file is resolved and must give no errors and exactly the documented values**;
- JSON blocks that are not tool calls are excluded from the tool-schema check.
```
$ python -m pytest tests/test_tool_registry_doc.py -q
14 passed in 18.46s
```
