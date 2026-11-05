# T-03366 Evidence: Tool Registry & Taxonomy — data model Implementation

- Date: 2026-11-06
- Spec: [T-03364-spec.md](T-03364-spec.md). Module: `code/aiosh-mcp/aiosh_mcp/tool_registry_data_model.py`.
- Tests were written first: `tests/test_tool_registry_data_model_impl.py` failed at collection while the catalog was still a stub.

## What was implemented
- **`ToolEntry.validate()`** runs in `__post_init__`, so an invalid entry cannot exist. It checks:
  - canonical regex and length (lower-case dotted, ≤ 64);
  - MCP names (≤ 8, existing MCPDM identifier rule);
  - title (1..64, no control or bidi characters);
  - exact enum types and real `bool` flags;
  - the five §2.3 consistency rules.
- **`ToolCatalog`**:
  - case-insensitive (NFKC + casefold) uniqueness across all canonical and MCP names; ≤ 512 entries;
  - `get` / `resolve` (exact) / `profile` (never raises) / `require`;
  - `entries()` sorted; `names()` read-only;
  - deterministic `export_json()` (`schema_version: 1`);
  - `annotations()` derived from the entry.
  The catalog is immutable: `__slots__`, `__setattr__` raises, `MappingProxyType`, and no add/remove methods.
- **`unknown_profile`**: fail closed (destructive, irreversible, needs a grant, open-world; network scope for
  `pentest.`/`network.`, else path). A malformed name becomes `"unregistered"`, never echoed.
- **Error messages** truncate names to 80 chars and strip control/bidi characters.
- **`default_catalog()`** (built once) has 18 entries: the 9 `agent_bridge.CANONICAL_TO_MCP` tools,
  `aios.agent_loop.{start,step,abort,complete,recover}`, `audit.rotate`, and `fs.write` / `system.reboot` / `system.shutdown`.
  - Agent-loop entries reproduce the published `agent_loop_mcp.TOOL_ANNOTATIONS` exactly (tested).
  - No enforcement path uses the catalog yet (spec §1). Server import is unchanged.

## Results
```
$ python -m pytest tests/test_tool_registry_data_model_impl.py tests/test_tool_registry_data_model_scaffold.py -q
32 passed in 2.15s
$ python -c "import aiosh_mcp.server; ..."   -> 18 entries
```
Drift preview (spec §5): for all 18 entries, `irreversible` agrees with both `audit_client.grant_check`'s name rule and
`agent_loop_policy.is_irreversible`. **0 disagreements.** The known disagreements (research B4.4/B4.5) concern tools not yet
seeded (`process.*`, `shell.*`, the Rust reversible pentest tools); the unit-test task makes this a permanent check.

No new dependency (`mcp.types.ToolAnnotations` is the already-used SDK). No audit rows and no persistence: the model is read-only.
