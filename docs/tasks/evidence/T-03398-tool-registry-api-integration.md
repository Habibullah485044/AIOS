# T-03398 Evidence: Tool Registry & Taxonomy — API surface Integration

- Date: 2026-11-06
- Production surface: the real MCP server (`python -m aiosh_mcp.server`) over stdio, seen by an MCP client (`mcp` SDK
  `ClientSession`). `server.py` registers the two new tools and runs `apply_catalog_annotations` after every other registration (T-03396).

## Test (`code/aiosh-mcp/tests/test_tool_registry_api_integration.py`)
What a real client sees:
- `tools/list`: **every** tool carries annotations, and every listed tool resolves in the catalog.
- Every tool advertised `readOnlyHint=true` is a catalog `read_only`, grant-free entry.
- `aios_pentest_nmap` is not read-only and not closed-world; `aios_audit_tail` is advertised read-only.
- `aios_tool_registry_decide("aios_pentest_nmap")` → canonical `pentest.nmap`, irreversible, `target_checked: false`.
- `aios_tool_registry_stats` reflects the calls just made (decisions ≥ 2, unregistered ≥ 1, mode `shadow`) and does not contain the queried
  unknown name.
- A 300-char name is rejected by the published schema over the wire (`isError`).
```
$ python -m pytest tests/test_tool_registry_api_integration.py -q
1 passed
```

Server-side enforcement is unchanged: the full classified suite with the annotation pass applied gives the same baseline
(T-03396: 1 803 tests, 136 missing-binary failures plus the known flake).
Cross-substrate: annotations are an MCP-surface feature only. The TS and Rust MCP manifests are separate (research T-03363 B1), and their
annotations remain a follow-up.
