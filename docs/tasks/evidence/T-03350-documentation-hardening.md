# T-03350 Evidence: Agent Loop Hardening — documentation Hardening

- Date: 2026-11-05

## Changes
| Gap | Fix |
|---|---|
| One failing section builder (e.g. an import error after a refactor) made `reference()` with no section raise, so the MCP `aios_agent_loop_doc` call and the CLI `doc` returned no reference at all. | `reference()` with no section builds each section independently. A failing section is omitted and reported as `_unavailable: {section: ExceptionType}`. Only the exception **type** is reported; messages can carry paths. |
| Cached failures | Confirmed: `lru_cache` does not cache exceptions, so a transient failure recovers on the next call (tested). |
| Output size | The whole reference serialises to JSON at **~15.9 KB**. A guard test keeps it under 256 KiB. |

Error envelope: a single-section failure still surfaces through the MCP `_run` envelope (`LOOPSERV_ERR_INTERNAL`) or CLI exit 1, never a traceback.
No resources are held (pure in-process build), so there is nothing to clean up.

## Tests (`tests/test_agent_loop_doc_hardening.py`, 3)
```
3 passed in 1.92s
```
Against the old code: `test_one_broken_section_degrades_not_fails` **fails**; the other two (cache recovery, size) pass, as they describe behaviour that was already correct.
