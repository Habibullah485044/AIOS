# T-03369 Security Review: Tool Registry & Taxonomy — data model

- Date: 2026-11-06
- Scope: `aiosh_mcp/tool_registry_data_model.py` (entries, catalog, fail-closed profile, derived annotations, seed data)
  and its MCP tools `aios_tool_registry_list` / `aios_tool_registry_get`.
- Method: an **independent read-only reviewer subagent** was given the code and spec only (not my conclusions).
  I reproduced the findings myself (#1, #3 and #4 by direct probe; #2 by reading `pentest.py`, where tshark and
  aircrack-ng dispatch with `target=pcap_path` / `target=capture_path`). Every fix has a regression test, run against
  the pre-fix code.

## Findings
| # | Sev | Finding | Status |
|---|---|---|---|
| 1 | Medium | **Seed data failed open.** `aios.fs.read` had `requires_grant=False`, but `server.aios_fs_read` calls `_recorded_call(require_grant=True)`. A future enforcement caller would have dropped the grant requirement. | **Fixed:** `grant=True`. |
| 2 | Medium | **Offline pentest tools were network-scoped.** `pentest.tshark` and `pentest.aircrack-ng` read a capture *file*. A caller picking its checker from `scope_kind` would run `network_allowed(path, [])` → `True`, while `path_allowed` refuses. Their effects were also wrong (aircrack was `destructive`). The validator forced network scope for every pentest tool. | **Fixed:** pentest ⇒ irreversible and path- **or** network-scoped. Both tools are now path-scoped, closed-world and `additive`, still irreversible and grant-gated. The disagreement with `grant_check`'s name rule is listed explicitly in the drift test (`KNOWN_SCOPE_DISAGREEMENTS`), not hidden. |
| 3 | Medium | **Entries could be weaker than today's enforcement.** The irreversible rule was by *category*, while `grant_check` and `agent_loop_policy` decide by *name*. The validator accepted `fs.write_all` as read-only with no grant, `system.reboot` as an additive admin tool, `shell.exec` / `process.kill` as reversible, and a `network` tool with scope `none`. | **Fixed:** `irreversible_by_name()` = the union of both existing name rules (case-insensitive). Any matching entry must be irreversible **and** require a grant. Category `network` ⇒ network scope (⇒ open world). |
| 4 | Low | Unknown-name scope inference was case-sensitive and ignored the bare `pentest` / `network` names that `agent_loop_gate` treats as network. | **Fixed:** `network_by_name()` casefolds and includes the bare names. |
| 5 | Low | Every malformed name, and the literal name `unregistered`, collapsed to one canonical `"unregistered"`, so one grant naming it would cover them all. | **Fixed:** each malformed name gets `unregistered.<sha256[:16]>` (distinct, never echoes the raw name). That prefix cannot be registered. A well-formed unknown name keeps its own name. |
| 6 | Low | `pentest.aircrack-ng` and `pentest.aircrack_ng` could coexist. The fold ignored separators. | **Fixed:** the collision fold treats `.`, `_` and `-` as one separator. An alias may fold onto its *own* canonical name (`aios_fs_read` ~ `aios.fs.read`); any other collision is `TOOLREG_ERR_DUPLICATE`. |
| 7 | Info | Immutability is by convention: in-process code can use `object.__setattr__`, `gc` or enum `_value_` tricks. | **Accepted, documented.** Python cannot prevent same-process tampering. There is no external (MCP/CLI) route to change the catalog. |
| 8 | Info | A `str` subclass with custom `__eq__`/`__hash__` could resolve to another entry. | **Fixed:** lookups require `type(name) is str`. Anything else gets the fail-closed profile. |
| 9 | Info (suspected) | A per-name `irreversible` flag cannot express per-call irreversibility (an `aios.agent_loop.step` can be irreversible by C-3 classification). | **Documented** for the docs task: the catalog flag is a *floor*; per-call classification can only add. |
| 10 | Info | The pentest tools are still served without MCP annotations. | Follow-up for the MCP epic: annotate served tools from the catalog. |

Checked and fine (reviewer): unknown names never inherit a registered profile; names are ASCII-only; `get` returns
canonical names only; annotations follow MCP 2025-06-18 semantics; the MCP surface rejects over-long, empty and
non-string names; hostile names are not echoed; listing is cheap.

## Regression tests (`code/aiosh-mcp/tests/test_tool_registry_data_model_security.py`, 16)
Result on pre-fix code (production module stashed): **16 failed**. On the fixed code: **16 passed**.
Existing tests updated where they pinned pre-review behaviour: pentest ⇒ path or network scope, synthetic
`unregistered.<hash>` names, and the explicit offline-pentest scope disagreement.
```
$ python -m pytest tests/ -k tool_registry -q
115 passed
```

## PoR standing rule
The catalog is read-only and changes no enforcement path yet. These fixes make sure that when callers migrate to it,
it is never weaker than today's name rules (I-2 grant requirement, the irreversible budget). **No bypass.**
