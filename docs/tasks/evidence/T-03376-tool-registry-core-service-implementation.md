# T-03376 Evidence: Tool Registry & Taxonomy — core service Implementation

- Date: 2026-11-06
- Spec: [T-03374-spec.md](T-03374-spec.md). Module: `code/aiosh-mcp/aiosh_mcp/tool_registry_service.py`.
- Tests were written first: `tests/test_tool_registry_service_impl.py` (12).

## What was implemented
- **The legacy rules, reproduced as enforced today:**
  - `legacy_requires_grant` and `legacy_scope` (`audit_client.grant_check`, case-sensitive);
  - `legacy_irreversible` (calls `agent_loop_policy.is_irreversible`).
- **`ToolRegistryService.decide`:**
  - pure; never raises; non-`str` input gets the fail-closed profile;
  - `requires_grant` = catalog OR legacy OR caller flag;
  - `irreversible` = catalog OR legacy OR `irreversible_by_name` OR classifier C-3;
  - `scope_kinds` = legacy scope plus the catalog scope (both when they differ);
  - `disagreements` lists where the catalog differs from the legacy rules (and `unregistered`).
- **`enforcement()`:** `{}` in `shadow` (the default), the stricter-of-both fields in `strict`. Mode comes from the argument or
  `AIOSH_TOOL_REGISTRY_MODE`; any other value raises `TOOLSVC_ERR_MODE`.
- **`stats()`:** thread-safe counters (decisions, disagreements by kind, unregistered count) plus at most 50 **hashed**
  unregistered-name samples. Memory is bounded: the spec's "distinct unregistered names" is a count of unregistered decisions, plus the bounded sample.
- **`report()`:** one masked (`mask_secrets`, ≤ 64 chars) JSON line on stderr per disagreeing decision; nothing when the two agree. A closed
  stderr is ignored. **No audit row, no DB, no file** (TOOLSVC-INV3).
- **`service()`:** a lazily built, lock-protected process singleton.

## Results
```
$ python -m pytest tests/ -k tool_registry -q
139 passed, 1437 deselected, 1 warning in 14.03s
```
- **TOOLSVC-INV1 (never weaker)** is tested over every catalog name, 7 legacy edge names and 500 random names, with and without
  the caller's grant flag. Grant, irreversibility and legacy scope are always at least as strict as the legacy rules.
- **Disagreements over the catalog's canonical names (9; all expected):**
  - `grant` ×7: `aios.agent_loop.{start,step,abort,complete,recover}`, `audit.rotate`, `aios.fs.read`. The catalog says a
    grant is required, while `grant_check`'s generic name rule does not. These surfaces enforce their grant themselves (loop tokens,
    `require_grant=True`).
  - `scope` ×2: `pentest.tshark`, `pentest.aircrack-ng` (path-scoped offline tools, T-03369 #2).
- Over **served MCP names** the counts are much larger (grant 64, irreversible 57, unregistered 52, scope 3). That is because the legacy rules
  only understand canonical names, and 52 served tools are unregistered and so get the fail-closed profile. **This is why strict mode stays
  opt-in until coverage is complete** (research D1, D4).

No caller is wired yet (integration task). No new dependency.
