# T-03370 Evidence: Tool Registry & Taxonomy — data model Hardening

- Date: 2026-11-06
- Scope: failure modes of `tool_registry_data_model` and its MCP registration.
  The module runs no processes and opens no files, DBs or sockets, so the questions are availability,
  explicit errors and bounded cost.

## Gaps found and fixed
| Failure mode | Before | After |
|---|---|---|
| **Catalog fails to build** (a bad seed edit) | `register_tool_registry_tools` raised during `server.py` import: **all 69 MCP tools gone** (probe: `SERVER IMPORT FAILED: ToolRegistryError TOOLREG_ERR_DUPLICATE`). | The server still imports and serves every tool. `aios_tool_registry_list` / `get` answer with the new **`TOOLREG_ERR_UNAVAILABLE`** envelope (`ok: false`, code, reason code), and `get` still returns the fail-closed unknown profile. The failure is reported on stderr. CI still fails, because the registry tests build the catalog directly. |
| **Same entry object listed twice** | Accepted: the "alias may fold onto its own canonical" rule from T-03369 compared entry identity. Found by the probe above. | `TOOLREG_ERR_DUPLICATE: entry … is listed twice`. |
| Output size | Not measured | The largest possible catalog (512 entries, every name and title at maximum length, 8 aliases each) exports **< 1 MiB**, well under MCP's 10 MiB payload bound. |
| Lookup cost | Not measured | 20 000 `profile()` calls on a 512-entry catalog, misses included: **< 2 s** (O(1) dict lookups). |
| Resources | — | The module source contains no `open(`, `sqlite3`, `subprocess`, `socket` or `Thread(` (tested), so there is nothing to leak or clean up. |

Error envelope: every MCP path returns `{"ok": …}`. Schema violations are rejected by FastMCP before the tool runs
(T-03368), and a broken catalog gives `TOOLREG_ERR_UNAVAILABLE`. There are no silent failures.
Fail-open honesty (ADR-0035 §F-2): the registry writes no audit rows. Its degraded mode is explicit in the envelope and
on stderr, and lookups stay fail-closed.

## Tests (`code/aiosh-mcp/tests/test_tool_registry_data_model_hardening.py`, 4)
| Test | Old code | New code |
|---|---|---|
| broken catalog degrades two tools, not the server (subprocess) | **fails** (import error) | passes |
| same entry listed twice is rejected | **fails** | passes |
| largest possible catalog stays bounded (size + lookup cost) | passes (already bounded; on the first run it failed only because of a 65-char name in the test, since fixed) | passes |
| registry holds no resources | passes | passes |
```
$ python -m pytest tests/ -k tool_registry -q
119 passed, 1437 deselected, 1 warning in 16.04s
```
