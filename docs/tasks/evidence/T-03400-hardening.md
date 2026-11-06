# T-03400 Evidence: Tool Registry & Taxonomy — API surface Hardening

- Date: 2026-11-06
- Scope: failure modes of `apply_catalog_annotations`, which runs during `server.py` import (a failure there would take all 71 tools
  down), and of the decide/stats tools.

## Gaps found (probe) and fixed
| Failure mode | Before | After |
|---|---|---|
| A tool whose input schema is not a dict (a list or string; e.g. a future hand-written tool) | `unsafe_for_read_only_hint` raised `AttributeError`, so the pass raised and **server import aborted** (probe: `apply RAISES AttributeError -> would abort server import`) | an unreadable schema counts as **unsafe**: no read-only hint (fail closed), no exception |
| Any exception while annotating one tool | aborted the whole pass and the server import | per-tool isolation: the tool keeps exactly its previous annotation, `errors` is counted, one line goes to stderr, and the rest of the pass continues |
| A broken catalog | already handled (T-03396): nothing changed, `{"error": "TOOLREG_ERR_UNAVAILABLE"}` | unchanged |
| decide/stats with a broken service | already handled (T-03396): `TOOLREG_ERR_UNAVAILABLE` envelope | unchanged |

Envelope: the pass returns `{"applied", "unchanged", "skipped_unregistered", "errors"}`, and the tools return `{"ok", ...}` or the
unavailable envelope. There are no silent failures.
Cleanup: no resources held (pure in-memory pass). Retries and timeouts: not applicable (no I/O).

## Tests (`code/aiosh-mcp/tests/test_tool_registry_api_hardening.py`, 7)
| Test | Old code | New code |
|---|---|---|
| unreadable schemas (list, str, int, non-container `properties`) fail closed | **fails** ×5 | passes |
| a missing or `None` `properties` is not unsafe | passes | passes |
| one broken tool does not stop the pass: the other tool is annotated, the broken one is unchanged, and an unreadable schema gets no read-only hint | **fails** | passes |

Result on pre-fix code: **6 failed, 1 passed**.
```
$ python -m pytest tests/ -k tool_registry -q
420 passed, 1 skipped, 1437 deselected, 1 warning in 38.57s
```
