# T-03393 Research: Tool Registry & Taxonomy — API surface

- Date: 2026-11-06
- Question: what MCP API should the tool registry expose beyond `aios_tool_registry_list` / `_get` (T-03368), and should the
  catalog drive the `ToolAnnotations` of every served tool?
- Method: measured against the live server (`mcp._tool_manager.list_tools()`), and re-read the MCP annotation semantics already cited in
  [T-03363](T-03363-research.md) (E2/E3). **No code was changed.**

## A. Facts
- The server serves **69** MCP tools, and the catalog covers all of them (T-03380).
- **Only 14 of 69 carry `ToolAnnotations`:** the 12 agent-loop tools and the 2 registry tools. Under MCP's defaults (`readOnlyHint=false`,
  `destructiveHint=true`, `openWorldHint=true`; E2) clients treat the other **55 as destructive and open-world**, including pure reads
  such as `aios_audit_tail` or `model_backend_list`. That is conservative but noisy: clients prompt for confirmation on reads.
- Of the 14 annotated tools, **7 differ from the catalog-derived annotations**: the read-only agent-loop tools snapshot, list, history,
  config, metrics, validate and doc. The difference is only `destructiveHint` / `idempotentHint`: the agent-loop module sets
  `False` / `True`, while the catalog leaves them `None` for read-only tools. The spec calls them "meaningful only when
  `readOnlyHint == false`" (E2), so the difference has no semantic effect. The 5 mutating agent-loop tools and both registry tools agree exactly.
- FastMCP sets annotations at registration (`Tool.annotations`, `mcp/server/fastmcp/tools/base.py:37`). Changing them later means
  replacing the registered tool's `annotations` attribute before the server starts serving, or passing them at registration.
- The registry service has per-process counters (`stats()`, `report_stats()`). The server process is where they mean something; the
  CLI deliberately does not expose them (T-03383 D5).

## B. Security consideration (the main decision)
Annotations are **hints for clients**, and the spec says clients must not trust them from untrusted servers (E3). For a *trusted* AIOS server, some
clients *will* use them. A tool marked `readOnlyHint=true` may be auto-approved without a confirmation prompt. So:
- Deriving annotations from the catalog **removes confirmations** for tools the catalog says are read-only. That is only as safe as the
  catalog is accurate. A wrong `read_only` entry would turn a consequential tool into a silently auto-approved one at the client.
- Server-side enforcement (PEP grants, the classifier, the irreversible budget) is unaffected either way. Annotations never relax it.

## C. Decisions needed
| # | Decision | Recommendation |
|---|---|---|
| D1 | New read-only tools | `aios_tool_registry_decide(name, require_grant=false)` returns the service decision with `target_checked: false`. `aios_tool_registry_stats()` returns the **server's** decision counters and report stats. Both are read-only with no token, and their own catalog entries are added. |
| D2 | Catalog-driven annotations for all served tools | Apply them **only where they make a tool look *more* careful, or are equivalent**: set `destructiveHint` / `openWorldHint` / `readOnlyHint=false` from the catalog. Mark `readOnlyHint=true` only for entries that are `read_only` **and** `requires_grant=false` **and** in category `audit` / `agent_loop` / `mcp_core` / `model_backend` / `fs.read`. Leave existing explicit annotations that disagree only on meaningless hints (A, the 7 tools) as they are. Report any disagreement in a drift test. |
| D3 | When annotations are applied | Once, at the end of `server.py` registration, by `apply_catalog_annotations(mcp)`, so registration order does not matter. A broken catalog leaves annotations untouched (T-03370 pattern). |
| D4 | Drift test | Every served tool's annotations must be *at least as cautious* as the catalog-derived ones, and the 7 known equivalent differences are listed explicitly. |
| D5 | Errors | Reuse `TOOLREG_ERR_UNAVAILABLE` and `TOOLREG_ERR_UNKNOWN`. No new codes. |
