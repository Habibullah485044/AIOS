# T-03394 Specification: Tool Registry & Taxonomy — API surface

- Date: 2026-11-06
- Inputs: [T-03393-research.md](T-03393-research.md). D1–D5 are adopted.
- Module: `code/aiosh-mcp/aiosh_mcp/tool_registry_api.py` (new, AIOS-specific). It registers the two new tools and applies catalog
  annotations. The existing `register_tool_registry_tools` (list/get) is unchanged.
- Invariants `TOOLAPI-INV1..INV4`. No new error codes: `TOOLREG_ERR_UNAVAILABLE` and `TOOLREG_ERR_UNKNOWN` are reused.

## 1. New MCP tools (read-only, no token)
| Tool | Arguments | Result `data` |
|---|---|---|
| `aios_tool_registry_decide` | `name: str (1..256)`, `require_grant: bool = false` | the `ToolDecision` fields (scope kinds as strings) + `target_checked: false`, from the **server's** service instance (so the call counts in its stats) |
| `aios_tool_registry_stats` | — | `service`: the server's `ToolRegistryService.stats()` (mode, decisions, disagreements by kind, unregistered count, hashed samples, catalog size); `reports`: `report_stats()` (lines written, suppressed) |

Envelope: `{"ok": true, "data": …}`. If the catalog or service is unavailable: `{"ok": false, "error_code": "TOOLREG_ERR_UNAVAILABLE", "error": …}`.
Their catalog entries are `aios.tool_registry.decide` and `aios.tool_registry.stats` (`mcp_core`, `read_only`, no grant). Their annotations
are derived from those entries.

## 2. Catalog-driven annotations (`apply_catalog_annotations(mcp_app) -> dict`)
Called once at the end of `server.py`. For every served tool `t` with catalog entry `e = catalog.resolve(t.name)`:
- **Never relax.** The applied annotation is the *more cautious* of the existing one and the catalog-derived one, field by field:
  - `readOnlyHint`: `true` only if the catalog says `read_only` **and** `e.requires_grant` is false **and** `e.category` is one of
    `audit, agent_loop, mcp_core, model_backend, fs.read, service`. Otherwise it is `false` when either side says false or omits it.
  - `destructiveHint`: `true` if either side says true (or omits it while not read-only).
  - `openWorldHint`: `true` if either side says true.
  - `idempotentHint`: kept only when both agree; otherwise `None`/false.
- A tool that already has annotations equivalent under MCP semantics (read-only, where the destructive and idempotent hints are
  meaningless) keeps them unchanged.
- Returns `{"applied": n, "unchanged": m, "skipped_unregistered": k}`. If the catalog is broken, nothing is changed and
  `{"error": "TOOLREG_ERR_UNAVAILABLE"}` is returned (the server still starts).

## 3. Invariants
- **TOOLAPI-INV1 (read-only):** the new tools and the annotation pass change no catalog, DB or audit row.
- **TOOLAPI-INV2 (annotations only grow caution):** after `apply_catalog_annotations`, no tool is *less* cautious than before
  (readOnly→true only under §2's conjunction; destructive and openWorld never go true→false).
- **TOOLAPI-INV3 (server-side enforcement untouched):** PEP, classifier and budget decisions are identical before and after (annotations
  are client hints). Proven by the full suite baseline.
- **TOOLAPI-INV4 (bounded):** `stats` output is bounded by the service's bounds (≤ 50 samples, fixed keys).

## 4. Audit and persistence effects
None.
