# Tool Registry & Taxonomy — data model

- Module: `code/aiosh-mcp/aiosh_mcp/tool_registry_data_model.py`
- Lifecycle: T-03363..T-03372 (Phase 3 — AI Control Plane / Tool Registry & Taxonomy / data model)
- Status: shipped. Read-only. **No enforcement path uses it yet.** Callers migrate in later epics.

## 1. What it is
One trusted, server-side description per tool:
- the **canonical** dotted name used in PEP grants and audit rows (`pentest.nmap`, `aios.agent_loop.step`);
- the **MCP names** clients call (`aios_pentest_nmap`, `aios_agent_loop_advance`);
- the tool's **taxonomy**: what kind of thing it does, and whether it is irreversible or scoped by path or network.

Before this, the same facts were scattered across at least eight name-based rules in three languages, and they
disagreed (research: [T-03363](tasks/evidence/T-03363-research.md)).

MCP `ToolAnnotations` are **derived** from an entry and never read. Per MCP 2025-06-18, annotations are untrusted hints, so
enforcement must come from a server-side source like this one.

## 2. Taxonomy
| Field | Meaning |
|---|---|
| `canonical` | lower-case dotted name, ≤ 64 chars, `^[a-z][a-z0-9_-]*(\.[a-z0-9_-]+)*$` |
| `mcp_names` | ≤ 8 aliases, each ≤ 64 chars of `A-Z a-z 0-9 _ . -` |
| `category` | `fs.read`, `fs.write`, `process`, `audit`, `pentest`, `network`, `gui`, `system`, `agent_loop`, `model_backend`, `mcp_core`, `service`, `admin` |
| `effect` | `read_only`, `additive`, `destructive` |
| `irreversible` | counts against a grant's `max_irreversible` |
| `scope_kind` | `none`, `path`, `network`: which grant scope applies to its targets |
| `open_world` | talks to external hosts |
| `requires_grant` | a PEP grant is needed even for a user-issued call |
| `idempotent` | repeating the call has no further effect (meaningless for `read_only`) |

**Consistency rules** (TOOLREG-INV1): an entry that breaks one cannot be constructed.
1. `read_only` ⇒ not irreversible, not idempotent.
2. irreversible ⇒ requires a grant and is not `read_only`.
3. network scope ⇒ open world.
4. `pentest` ⇒ irreversible and path- or network-scoped. Offline tools such as `tshark -r` and `aircrack-ng` read a file, so they are path-scoped.
5. `fs.write` and `system` categories ⇒ irreversible.
6. `network` category ⇒ network scope.
7. **Never weaker than today's name rules:** a name that `audit_client.grant_check` or `agent_loop_policy` treats as
   irreversible (`pentest.*`, `fs.write*`, `process.*`, `shell.*`, `system.reboot`, `system.shutdown`, case-insensitive) must be
   irreversible and require a grant.

**Names** (TOOLREG-INV2) are unique across the catalog after NFKC, case-folding, and treating `.`, `_` and `-` as one separator. An
alias may fold onto its own canonical name (`aios_fs_read` ~ `aios.fs.read`); any other collision is rejected.

## 3. Lookups
| Call | Behaviour |
|---|---|
| `get(canonical)` | the entry or `None`; canonical names only |
| `resolve(name)` | exact canonical **or** MCP name, else `None`; exact `str` only |
| `profile(name)` | `resolve(name)` or the **fail-closed unknown profile**; never raises |
| `require(name)` | the entry, else `TOOLREG_ERR_UNKNOWN` |
| `annotations(name)` | MCP `ToolAnnotations` derived from the entry |
| `export_json()` | deterministic JSON (`schema_version: 1`) for other substrates |

**Unknown tools fail closed** (TOOLREG-INV3): an unregistered name is treated as destructive, irreversible, grant-required and
open-world. It is network-scoped if its name is `pentest`/`network` or starts with `pentest.`/`network.` (case-insensitive), else
path-scoped. A malformed name gets a distinct synthetic canonical name `unregistered.<sha256[:16]>`, so the raw name is never
echoed and one grant cannot cover several malformed names. Names with that prefix cannot be registered.

The catalog is immutable (TOOLREG-INV5): frozen entries, a read-only name map, and no add/remove methods. No MCP or CLI tool can change
it; it is code, reviewed through PRs.

## 4. Use it

Python (copy-pasteable; the doc test runs it):
```python
from aiosh_mcp.tool_registry_data_model import default_catalog

catalog = default_catalog()
nmap = catalog.resolve("aios_pentest_nmap")              # MCP alias -> entry
print(nmap.canonical, nmap.irreversible, nmap.scope_kind.value)
# -> pentest.nmap True network
unknown = catalog.profile("pentest.newthing")            # unregistered: fail closed
print(unknown.irreversible, unknown.requires_grant, unknown.scope_kind.value)
# -> True True network
print(catalog.annotations("aios_fs_read").readOnlyHint)
# -> True
```

MCP (read-only, no token):
```json
{"name": "aios_tool_registry_get", "arguments": {"name": "aios_pentest_nmap"}}
```
```json
{"name": "aios_tool_registry_list", "arguments": {"category": "pentest"}}
```
`aios_tool_registry_get` returns `{"ok": true, "data": {"registered": true|false, "entry": {...}}}`.

## 5. Errors
| Code | When |
|---|---|
| `TOOLREG_ERR_INVALID_NAME` | a canonical or MCP name fails its rule, a title has control or bidi characters, or a reserved `unregistered.` name is registered |
| `TOOLREG_ERR_INCONSISTENT` | a consistency rule (§2) fails, a field has the wrong type, or a catalog item is not a `ToolEntry` |
| `TOOLREG_ERR_DUPLICATE` | a name collision (§2), or the same entry listed twice |
| `TOOLREG_ERR_BOUNDS` | > 8 aliases, title not 1..64 chars, or > 512 entries |
| `TOOLREG_ERR_UNKNOWN` | `require` / `annotations` on an unregistered name |
| `TOOLREG_ERR_UNAVAILABLE` | the catalog failed to build. The two MCP tools answer with this instead of taking the server down; `get` still returns the fail-closed profile |

Errors are `ToolRegistryError(code, message)`. Messages echo names only with control and bidi characters stripped, truncated to 80 chars.

## 6. Coverage and drift checks
- The default catalog has **20 entries**: the 9 `agent_bridge` tools, 5 agent-loop names, `audit.rotate`, `fs.write`,
  `system.reboot`, `system.shutdown`, and the registry's own two tools. It covers **17 of the 69** served MCP tools. The
  integration test tracks, but does not fail on, the uncovered ones.
- Permanent tests (CI suite #35 `tool_registry`) assert, for every entry, agreement with `audit_client.grant_check`, `agent_loop_policy`,
  the network-name rule and TS `isIrreversible`. The one listed exception: `pentest.tshark` / `pentest.aircrack-ng` are
  path-scoped here, while `grant_check`'s name rule would apply `scope.networks` to them.

## 7. Known limitations
- **Not enforcing yet.** The PEP, the agent-loop policy and dispatch still use their own name rules. This catalog only describes, and the
  drift tests keep the two in step.
- **Per-name, not per-call.** `irreversible` is a floor. A call can still be irreversible by the classifier's C-3 flag (for example one
  `aios.agent_loop.step`); per-call classification can only add to it.
- **Partial coverage:** 17 of 69 served tools.
- **Annotations are not yet applied** to the served pentest and core tools. Only the registry's own tools use catalog-derived annotations.
- **In-process immutability is by convention.** Python code in the same process can still mutate objects with `object.__setattr__` or `gc` tricks.
  There is no external route.
- **Substrates:** TS and Rust do not read `export_json()` yet. Rust's `is_irreversible` still treats four pentest discovery tools as
  reversible (research B4.4).

## 8. Evidence
[research](tasks/evidence/T-03363-research.md), [spec](tasks/evidence/T-03364-spec.md),
[scaffold](tasks/evidence/T-03365-tool-registry-data-model-scaffold.md),
[implementation](tasks/evidence/T-03366-tool-registry-data-model-implementation.md),
[unit](tasks/evidence/T-03367-tool-registry-data-model-unit-test.md),
[integration](tasks/evidence/T-03368-tool-registry-data-model-integration.md),
[security](tasks/evidence/T-03369-security.md), [hardening](tasks/evidence/T-03370-tool-registry-data-model-hardening.md)
