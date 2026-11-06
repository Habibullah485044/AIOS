# T-03396 Evidence: Tool Registry & Taxonomy — API surface Implementation

- Date: 2026-11-06
- Spec: [T-03394-spec.md](T-03394-spec.md). Module: `code/aiosh-mcp/aiosh_mcp/tool_registry_api.py`, wired into `server.py` after all
  other registrations.
- Tests were written first: `tests/test_tool_registry_api_impl.py`.

## What was implemented
- **`aios_tool_registry_decide(name, require_grant=false)`:** the *server's* `ToolRegistryService` decision (it counts in that service's
  stats), with `target_checked: false`.
- **`aios_tool_registry_stats()`:** the server's service counters and report stats. A broken registry gives a `TOOLREG_ERR_UNAVAILABLE`
  envelope. Both tools are read-only with no token; catalog entries `aios.tool_registry.decide` / `.stats` were added (73 entries).
- **`more_cautious(existing, derived, allow_read_only)`:** a field-by-field merge that **never relaxes**:
  - `readOnlyHint` becomes true only if the catalog allows it (read-only, no grant, one of the six categories) **and** the existing annotation
    does not explicitly say false. An omitted annotation has no opinion; this resolves an ambiguity in the spec text.
  - destructive and open-world stay true if either side says so (an omitted hint counts as MCP's default, true).
  - idempotent is claimed only if both sides claim it.
  - annotations equivalent under MCP semantics are returned as the same object (so the 7 read-only agent-loop tools keep theirs).
- **`apply_catalog_annotations(mcp)`:** applies the merge to every served tool. A broken catalog changes nothing.

## Results
```
$ python -m pytest tests/ -k tool_registry -q
388 passed, 1 skipped, 1437 deselected, 1 warning in 40.44s
live server: 71 served; 71 annotated (was 14 of 69); 40 advertised readOnlyHint=true
```
- **TOOLAPI-INV2 (never relaxes):** tested exhaustively over 3 existing × 2 derived × 2 allow combinations. Every served `readOnlyHint=true`
  tool is checked against the conjunction. Pentest, backup, release and agent-loop abort still look consequential, and pentest stays
  open-world.
- **TOOLAPI-INV3 (enforcement untouched):** full suite with annotations applied:
  ```
  137 failed, 1660 passed, 6 skipped, 23 deselected, 5 warnings in 190.84s (0:03:10)
  tests=1803 failures=137 errors=0 skipped=6
  missing-Rust-binary failures: 136
  other failures: ['tests.test_runbook_config_integration::test_integration_dynamic_session_capping_via_env :: assert True is False']
  ```
  This is the same classified baseline as before.
- The operator doc's coverage line was updated to 73 entries / 71 served tools; the doc drift test passes.
