# T-03374 Specification: Tool Registry & Taxonomy — core service

- Date: 2026-11-06
- Inputs: [T-03373-research.md](T-03373-research.md). Decisions D1–D6 are adopted as recommended.
- New module (AIOS-specific): `code/aiosh-mcp/aiosh_mcp/tool_registry_service.py`.
- Error prefix `TOOLSVC_ERR_*`; invariants `TOOLSVC-INV1..INV5`.

## 1. Purpose
A pure decision service over the immutable catalog. For one tool call it answers: what the tool is called canonically, whether it is
registered, whether it needs a grant, whether it is irreversible, which grant scope applies, and **where the catalog disagrees
with the legacy name rules**. In this epic it runs in **shadow mode**: production gates call it and report disagreements, but enforcement is
unchanged. A strict mode exists, defaults off, and can only make decisions stricter.

## 2. Types
### `ToolDecision` (frozen)
| Field | Type | Meaning |
|---|---|---|
| `canonical` | `str` | catalog canonical name, or the queried name / `unregistered.<hash>` from the fail-closed profile |
| `registered` | `bool` | the name resolved to a catalog entry |
| `requires_grant` | `bool` | catalog `requires_grant` **or** the legacy rule (`grant_check` irreversible set) **or** the caller's `require_grant` |
| `irreversible` | `bool` | catalog `irreversible` **or** `irreversible_by_name` **or** classifier C-3 (when a classification is given) |
| `scope_kinds` | `tuple[ScopeKind, ...]` | scopes to check. Usually one; **both** `path` and `network` when the catalog and the legacy network rule disagree |
| `disagreements` | `tuple[str, ...]` | sorted subset of `DISAGREEMENT_KINDS` |
| `mode` | `str` | `shadow` or `strict` |

`DISAGREEMENT_KINDS = ("unregistered", "grant", "irreversible", "scope")`. Each means the catalog and legacy answers differ on that
field (or, for `unregistered`, that the name is not in the catalog).

### `ToolRegistryService`
| Member | Behaviour |
|---|---|
| `__init__(catalog=None, mode=None)` | `catalog` defaults to `default_catalog()`. `mode` defaults to the `AIOSH_TOOL_REGISTRY_MODE` env value. Valid modes are `shadow` (default) and `strict`; any other value raises `TOOLSVC_ERR_MODE`. |
| `decide(tool, target=None, classification=None, require_grant=False) -> ToolDecision` | Pure, no I/O, never raises for any `tool` value (non-`str` → unregistered fail-closed profile). |
| `enforcement(decision) -> dict` | In `strict` mode: `{"requires_grant", "irreversible", "scope_kinds"}` to enforce, combined with the legacy result by **OR**. In `shadow` mode: `{}`, meaning enforce the legacy result unchanged. |
| `stats() -> dict` | Counters `decisions`, `disagreements` (by kind) and `unregistered` (count of distinct names, plus up to 50 hashed samples). Bounded memory. |

Module helper: `service()` is a process-wide instance built once (lazily) from the default catalog and the env mode.

## 3. Invariants
- **TOOLSVC-INV1 (never weaker):** for every input, the decision's `requires_grant` / `irreversible` are ≥ the legacy rule's.
  `scope_kinds` contains the legacy scope whenever the legacy rule applies one. Tested exhaustively over all registered names and a
  random-name corpus.
- **TOOLSVC-INV2 (shadow changes nothing):** in `shadow` mode, every production call path returns exactly what it returned before
  this epic. Same verdicts, same audit rows (row count and content), for the existing smoke and battery suites.
- **TOOLSVC-INV3 (no extra audit rows):** the service writes no audit rows and opens no DB. Disagreements go to the structured
  stderr log line `tool_registry.disagreement` (tool name masked via `mask_secrets`, at most 64 chars) and to the counters.
- **TOOLSVC-INV4 (pure and bounded):** `decide` does O(1) lookups. Its counters and sample sets are bounded.
- **TOOLSVC-INV5 (strict only tightens):** `strict` can add a grant requirement, mark a call irreversible or add a scope check. It can
  never remove one.

## 4. Call sites (integration task)
- `_dispatch.dispatch`: before Gate #2, `d = service().decide(tool, target, require_grant=require_grant)`.
  Disagreements are logged; in `strict` mode, `require_grant` becomes `require_grant or d.requires_grant`.
- `agent_loop_policy.evaluate_step`: `irreversible = legacy or (strict and d.irreversible)`; disagreements are logged.
- Neither path may change its audit-row count.

## 5. Coverage (also this epic)
Add catalog entries for **every served MCP tool** and **every literal audit name** (research A2). When coverage reaches 100 %, the
integration test's "tracked" list must become empty and the test switches from reporting to failing.

## 6. Errors
| Code | When |
|---|---|
| `TOOLSVC_ERR_MODE` | invalid mode value (constructor or env) |

`decide` never raises. A broken catalog is handled as in T-03370: the service is unavailable, `service()` raises
`ToolRegistryError(TOOLREG_ERR_UNAVAILABLE)`, and callers in shadow mode **must** catch it and fall back to legacy-only behaviour, logging once.

## 7. Audit and persistence effects
None. No DB, no files, no audit rows. Only a stderr log line and in-memory counters.

## 8. Out of scope
- Replacing the legacy rules (option S3), and cross-substrate (TS/Rust) consumers.
- The CLI and MCP exposure of `stats()` (MCP/CLI and observability epics).
