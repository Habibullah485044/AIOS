# T-03364 Specification: Tool Registry & Taxonomy — data model

- Date: 2026-11-06
- Inputs: research [T-03363-research.md](T-03363-research.md). Decisions D1–D7 are adopted as recommended there,
  except where this spec says otherwise.
- Module (new, AIOS-specific): `code/aiosh-mcp/aiosh_mcp/tool_registry_data_model.py`.
- Error prefix: `TOOLREG_ERR_*`. Invariants: `TOOLREG-INV1..INV6`.

Everything below is an **AIOS-specific** design. The only upstream contract used is MCP's `Tool` / `ToolAnnotations`
(MCP 2025-06-18, research E1–E3). No upstream API is invented.

## 1. Purpose
One trusted, server-side description per tool: what it is called on each surface, what kind of thing it does, and
whether it is irreversible or scoped by path/network. Later tasks migrate the eight name-based rules (research B3)
onto this model. **This epic's data model changes no enforcement path.** It adds the model and drift tests that
expose disagreements.

## 2. Types
### 2.1 Enums (closed; string values are the wire form)
| Enum | Values |
|---|---|
| `Category` | `fs.read`, `fs.write`, `process`, `audit`, `pentest`, `network`, `gui`, `system` (the TS `ToolClass` set, research B2), plus `agent_loop`, `model_backend`, `mcp_core`, `service` (task/compliance/runbook/release/backup), `admin` |
| `Effect` | `read_only`, `additive`, `destructive` |
| `ScopeKind` | `none`, `path`, `network` |

### 2.2 `ToolEntry` (frozen dataclass)
| Field | Type | Rule |
|---|---|---|
| `canonical` | `str` | Dotted canonical name used in grants and audit rows. 1..64 chars, `^[a-z][a-z0-9_-]*(\.[a-z0-9_-]+)*$` (lower-case, so case-variants cannot alias; research E6 says case-sensitive). |
| `mcp_names` | `tuple[str, ...]` | 0..8 MCP-surface aliases; each 1..64 chars, `^[A-Za-z0-9_.-]+$` (the existing `IDENTIFIER_RE` + `MAX_TOOL_NAME_LEN`). |
| `title` | `str` | 1..64 printable chars, no control or bidi characters (MCPDM-INV3). |
| `category` | `Category` | |
| `effect` | `Effect` | |
| `irreversible` | `bool` | Counts against a grant's `max_irreversible`. |
| `scope_kind` | `ScopeKind` | Which grant scope applies to its targets. |
| `open_world` | `bool` | Talks to external entities (network, other hosts). |
| `idempotent` | `bool` | Repeating the same call has no further effect. Meaningless for `read_only`. Default `False`. |
| `requires_grant` | `bool` | A PEP grant is required even for a user-issued call. |

`ToolEntry.validate()` runs in `__post_init__`, so no invalid entry can exist.

### 2.3 Consistency rules (TOOLREG-INV1)
An entry that breaks any rule is rejected with `TOOLREG_ERR_INCONSISTENT`:
1. `effect == read_only` ⇒ `irreversible is False` and `idempotent is False` (MCP says the idempotent hint is meaningless there; research E2).
2. `irreversible` ⇒ `requires_grant` and `effect != read_only`.
3. `scope_kind == network` ⇒ `open_world`.
4. `category == pentest` ⇒ `scope_kind == network` and `irreversible` (research D7: the stricter answer until a reviewed decision says otherwise).
5. `category in (fs.write, system)` ⇒ `irreversible`. This is the name rule `audit_client.grant_check` already enforces for `fs.write*`, `system.reboot` and `system.shutdown`.

### 2.4 `ToolCatalog`
An immutable collection built from a sequence of entries. `ToolCatalog(entries)` raises:
- `TOOLREG_ERR_DUPLICATE` if two entries share a `canonical`, two share an MCP name, or an MCP name of one entry equals another entry's canonical name. Comparisons are **case-insensitive** (TOOLREG-INV2), so `aios.FS.read` cannot shadow `aios.fs.read` on a case-folding client.
- `TOOLREG_ERR_BOUNDS` with more than `MAX_CATALOG_ENTRIES = 512` entries.

| Method | Returns | Failure |
|---|---|---|
| `get(canonical)` | `ToolEntry` or `None` | — |
| `resolve(name)` | the entry whose canonical **or** MCP name equals `name` (exact, case-sensitive), else `None` | — |
| `profile(name)` | `resolve(name)`, or the **fail-closed unknown profile** (§2.5) | never raises |
| `require(name)` | the resolved entry | `TOOLREG_ERR_UNKNOWN` |
| `entries()` | tuple sorted by `canonical` | — |
| `to_dict()` / `export_json()` | deterministic JSON (`schema_version: 1`, entries sorted, keys sorted) | — |
| `annotations(name)` | `mcp.types.ToolAnnotations` derived per §2.6 | `TOOLREG_ERR_UNKNOWN` |

### 2.5 Unknown tools fail closed (TOOLREG-INV3)
`profile(name)` for a name not in the catalog returns a synthetic, non-registered entry:
`effect=destructive, irreversible=True, requires_grant=True, open_world=True, idempotent=False`;
`scope_kind=network` if the name starts with `pentest.` / `network.` (the existing network rule), else `path`;
`category=admin`; `title="unregistered tool"`.
It is never added to the catalog, and its `canonical` is the queried name only when that name passes the canonical
regex. Otherwise it is `"unregistered"`, so a malformed name never reaches export or audit.

### 2.6 MCP annotations are derived, never read (TOOLREG-INV4)
`annotations(name)` → `ToolAnnotations(title=title, readOnlyHint=effect==read_only,
destructiveHint=(effect==destructive) if not read-only else None, idempotentHint=idempotent if not read-only else None,
openWorldHint=open_world)`.
Nothing in the model accepts annotations as input. Research E3: annotations are untrusted hints.

### 2.7 Immutability and bounds (TOOLREG-INV5 / INV6)
- Entries are frozen and the catalog holds tuples or a read-only mapping. There is no add/remove/update method, and
  **no MCP or CLI tool can change the catalog**: it is code, reviewed through PRs.
- Bounds: canonical ≤ 64, MCP names ≤ 64 and ≤ 8 per entry, title ≤ 64, catalog ≤ 512 entries. `TOOLREG_ERR_BOUNDS`.

## 3. Initial catalog (`DEFAULT_CATALOG`)
Built at import. It contains at least:
- every canonical name in `agent_bridge.CANONICAL_TO_MCP`, with that MCP name as alias;
- the agent-loop audit names `aios.agent_loop.{start,step,abort,complete,recover}`;
- `audit.rotate`;
- `fs.write`, `system.reboot`, `system.shutdown` (the irreversible names `grant_check` uses).

Entries for the rest of the ~67 served tools are added in the scaffold and implementation tasks. The drift test (§5)
reports served MCP tools with no entry, as a tracked list rather than a failure, until coverage is complete.

## 4. Errors
| Code | When |
|---|---|
| `TOOLREG_ERR_INVALID_NAME` | canonical or MCP name fails its regex or length |
| `TOOLREG_ERR_INCONSISTENT` | a §2.3 rule fails, or a field has the wrong type or an unknown enum value |
| `TOOLREG_ERR_DUPLICATE` | §2.4 uniqueness |
| `TOOLREG_ERR_BOUNDS` | §2.7 bounds |
| `TOOLREG_ERR_UNKNOWN` | `require` / `annotations` on an unregistered name |

All are raised as `ToolRegistryError(code, message)`. Messages echo a name only after it is truncated to 80 chars and
control characters are removed, so a hostile name cannot inject into logs.

## 5. Behaviour, failure path, and audit effects
- **Happy path:** `DEFAULT_CATALOG.profile("pentest.nmap")` returns the registered entry
  (`category=pentest, irreversible=True, scope_kind=network`); `resolve("aios_pentest_nmap")` returns the same entry.
- **Failure path:**
  - Constructing an invalid entry or catalog raises `ToolRegistryError` at import. A broken catalog therefore fails the
    test suite and the server start, never a request.
  - Lookups never raise except `require` and `annotations`.
- **Persistence:** none. No DB table and no file writes. The catalog is code; `export_json()` is for other substrates and docs.
- **Audit effects:** none in this task. The data model is read-only and writes no audit rows. Audit-relevant use comes when callers migrate.
- **Drift checks (unit/integration tasks):** for every registered entry, assert agreement with
  - `audit_client.grant_check`'s irreversible rule,
  - `agent_loop_policy.is_irreversible`,
  - the network rule.

  Disagreements are listed explicitly (research B4.4/B4.5), not hidden.

## 6. Reused vs new
| Reused | New |
|---|---|
| `IDENTIFIER_RE`, `MAX_TOOL_NAME_LEN`, MCPDM-INV3 control/bidi rejection (`mcp_server_core_data_model`) | `Category`, `Effect`, `ScopeKind`, `ToolEntry`, `ToolCatalog`, `ToolRegistryError`, `DEFAULT_CATALOG` |
| `mcp.types.ToolAnnotations` (upstream SDK) | `TOOLREG_ERR_*`, `TOOLREG-INV1..INV6` |
| `agent_bridge.CANONICAL_TO_MCP` (seed data) | |

## 7. Out of scope (later tasks or epics)
- Replacing the eight name-based rules with catalog lookups (core-service epic).
- Exposing the catalog over MCP/CLI (MCP/CLI epics; read-only by INV5).
- TS and Rust consumers of `export_json()`.
