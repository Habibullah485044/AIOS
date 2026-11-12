# T-03424 Specification: Tool Registry & Taxonomy — security policy

- Date: 2026-11-13
- Adopts [T-03423 research](T-03423-security-policy-research.md), decisions D1–D6. Python only (`code/aiosh-mcp`). Stdlib only.
- Everything here is **AIOS-specific**. No upstream API is assumed. MCP is touched only through the existing `aios_tool_registry_stats` tool.

## 1. Components
| Status | Interface | Role |
|---|---|---|
| **New** | `aiosh_mcp/tool_registry_policy.py` | The single policy point: `policy_revision()`, `evaluate()`, `grant_reason_suffix()`, `PolicyVerdict` |
| Reused | `tool_registry_service.service()`, `.decide()`, `.enforcement()`, `report()`, `intended_mode()` | Unchanged; `evaluate()` composes them |
| Changed | `_dispatch._registry_require_grant` | Becomes a thin call to `evaluate(..., surface="dispatch")`. The refusal reason gains `grant_reason_suffix()` |
| Changed | `agent_loop_policy._registry_irreversible` | Becomes a thin call to `evaluate(..., surface="agent_loop")` |
| Changed | `aios_tool_registry_stats` | `data.policy_revision` added (string) |

## 2. Contract
### 2.1 `policy_revision(catalog: ToolCatalog | None = None) -> str`
- Input: a catalog; default `default_catalog()`.
- Output: `"trp-" + sha256(canonical_json)[:16]`. `canonical_json` is the JSON array of
  `[canonical, effect, irreversible, requires_grant, scope_kind, open_world]` for every entry, sorted by `canonical`,
  with `separators=(",", ":")` and `ensure_ascii=True`.
- Titles, aliases, `category` and `idempotent` are **not** security fields: changing them keeps the revision.
- Deterministic across processes and hosts. Cached per catalog object. Never raises for a valid catalog.

### 2.2 `PolicyVerdict` (frozen dataclass)
| Field | Type | Meaning |
|---|---|---|
| `requires_grant` | bool | the caller's `require_grant` OR (strict) catalog / legacy grant rule |
| `irreversible` | bool | the caller's legacy irreversibility OR (strict) catalog irreversibility |
| `registry_added_grant` | bool | true iff `requires_grant` and the caller's `require_grant` was false, i.e. the registry made the grant necessary |
| `mode` | str | `shadow` \| `strict` (the intended mode if the service failed) |
| `revision` | str | `policy_revision()` or `""` if it could not be computed |
| `failure` | str \| None | exception type name if the registry failed, else `None` |

### 2.3 `evaluate(tool, target=None, *, surface, require_grant=False, legacy_irreversible=False, classification=None) -> PolicyVerdict`
- `surface` ∈ {`dispatch`, `agent_loop`}. Any other value is a programming error and raises `ValueError` (the only raise).
- **Happy path:** `d = service().decide(tool, target, classification=classification, require_grant=require_grant)`, `report(d, tool, surface)`,
  `e = service().enforcement(d)`. Then `requires_grant = require_grant or e.get("requires_grant", False)` and
  `irreversible = legacy_irreversible or e.get("irreversible", False)`.
- **Failure path:** any exception from the service: `failure = type(exc).__name__`. If `intended_mode() == "strict"`, both flags are true (fail closed).
  Otherwise the flags are the caller's own values. One stderr line per surface per process. Never stdout, never an audit row.
- Never raises for any `tool` / `target` / `classification` value (TOOLPOL-INV4).

### 2.4 `grant_reason_suffix(v: PolicyVerdict) -> str`
- `" (tool registry strict, catalog <revision>)"` iff `v.registry_added_grant` and `v.failure is None`.
- `" (tool registry unavailable, strict: fail closed)"` iff `v.registry_added_grant` and `v.failure`.
- `""` otherwise. Shadow mode never adds anything.

### 2.5 Dispatch refusal (existing row, existing column)
When `require_grant and grant_id is None`, `outcome_detail` / `reason` = `tool '<tool>' requires explicit PEP grant` + `grant_reason_suffix(v)`.
Every other refusal reason (classifier, `grant_check`, redeem) is unchanged.

## 3. Error cases
| Case | Result |
|---|---|
| Registry raises in shadow | legacy values; one stderr line; reason unchanged |
| Registry raises in intended strict | grant required, step irreversible; suffix `(tool registry unavailable, strict: fail closed)` |
| Unregistered tool, strict | `unknown_profile` requires a grant: refused without one, suffix names the catalog revision (D4: grant-required, not denied) |
| Bad `surface` | `ValueError` (caller bug; covered by unit test) |
| No new error codes | `TOOLREG_ERR_*` / `TOOLSVC_ERR_*` unchanged |

## 4. Persistence and audit effects
- No new files, tables, columns or audit rows. ADR-0035 §A F-2 holds: still exactly one row per MCP call.
- Only change: in strict mode the text of a grant refusal that the **registry** caused gains the suffix.

## 5. Invariants
- **TOOLPOL-INV1 (never weaker):** `requires_grant >= require_grant` and `irreversible >= legacy_irreversible`, for every input and mode.
- **TOOLPOL-INV2 (shadow is identical):** in shadow mode, every consumer's flags and reason strings are byte-identical to before this epic.
- **TOOLPOL-INV3 (attributable):** in strict mode, a refusal caused only by the registry names it and the catalog revision.
- **TOOLPOL-INV4 (total):** `evaluate` never raises except for a bad `surface`. It fails closed iff strict was intended.
- **TOOLPOL-INV5 (revision):** same security fields ⇒ same revision. Any change to a security field of any entry ⇒ a different revision.
- **TOOLPOL-INV6 (unconfigurable):** no config key, env var or argument changes the policy (locked keys of §6e unchanged).
- D5: `scope_kinds` stays unenforced. It is documented as a limitation and not part of this contract.

## 6. Acceptance tests (to be written in T-03427/T-03428)
- Unit: revision determinism and sensitivity (flip each security field of one entry ⇒ new revision; a title change ⇒ same).
  `evaluate` is OR-only over a grid of (mode × require_grant × legacy_irreversible), fails closed only when strict was intended, and returns the suffix forms.
- Integration: strict-mode `dispatch()` of a catalog-grant tool without a grant writes one refusal row whose reason ends with the
  suffix. The same in shadow is byte-identical to the old reason. `aios_tool_registry_stats` returns `policy_revision` equal to `policy_revision()`.

## Security audit (standing rule)
- Spec only, no code. The contract can only tighten (INV1) and keeps shadow identical (INV2). It adds attribution without new audit rows (F-2).
- Failure modes fail closed iff strict was intended (INV4). This matches the T-03379 behaviour it replaces. **No bypass.**
