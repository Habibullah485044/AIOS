# T-03343 Research: Agent Loop Hardening — documentation

- Date: 2026-11-05
- Scope: research only. **No code changed.**

## Facts (verified)
| # | Fact | Source |
|---|---|---|
| F1 | The operator doc `docs/SPEC-AGENT-LOOP-HARDENING-CORE-SERVICE.md` is now 393 lines across §1..§9 and has been edited by 6 epics. **Nothing checks it against the code.** | file; git log |
| F2 | Measured drift: **17 of 34 error codes** defined in `aiosh_mcp/agent_loop_*.py` are missing from the doc: all 7 `AGENTLOOPCONF_ERR_*`, all 4 `LOOPCLI_ERR_*`, 5 `LOOPDATA_ERR_*`, and `LOOPSERV_ERR_CIRCUIT_BREAKER`. Tools (9/9) and config fields (10/10) are covered. | scripted comparison (regex over module constants vs doc text) |
| F3 | `LOOPSERV_ERR_CIRCUIT_BREAKER` is **defined but never raised**. Breakers terminate the loop via the data model's `terminal_reason` text instead. A documented code that can never appear would mislead operators. | grep: 0 uses besides the definition |
| F4 | Precedent for in-product docs: `model_backend_adapters_doc.py` and `incident_runbook_doc.py` register `aios_*_doc_get/search/list` MCP tools over **hand-written topic text embedded in Python**. That is a third copy of the documentation, free to drift. | files |
| F5 | The spec doc is not packaged (`pyproject.toml` packages `aiosh_mcp*` only), so an installed server cannot read it. The machine-checkable facts (tools with schemas and annotations, error codes, config fields and bounds, CLI subcommands) all live in code. | `pyproject.toml` |
| F6 | The doc's runnable examples (§4 Python, §4a/§2b/§5b CLI sessions, §3 JSON calls) were verified by hand in their tasks. Only the §4 Python block has an automated re-check, and only once. | T-03281/T-03291/T-03301/T-03331/T-03341 evidence |

## Upstream references
- "Docs as code" / doctest-style verification (Python `doctest` concept): https://docs.python.org/3/library/doctest.html
- MCP `tools/list` already publishes the authoritative tool schemas (the server is the source of truth): https://modelcontextprotocol.io/specification/2025-03-26/server/tools
- Diátaxis (reference docs should be generated from, or checked against, the code they describe): https://diataxis.fr/reference/

## Assumptions
- A1: Agents benefit more from an accurate, code-generated reference served over MCP than from prose copied into Python strings (avoids F4).
- A2: A drift check that runs in CI catches the next 17 missing codes before an operator does.

## Decisions needed (for T-03344)
- D1: Add a **generated reference** `agent_loop_doc.reference()` built **from code**: tools (with schemas and annotations from the live registry), every
  error code with its module, config fields with defaults, bounds and env names, CLI subcommands, and the locked keys. (Recommended over F4's hand-written topics.)
- D2: Expose it as a read-only MCP `aios_agent_loop_doc(section?)` and a CLI `doc [--section S] [--json]`. (Recommended.)
- D3: Add a **drift test**: every generated item must appear in the spec doc, and every runnable example block (`python` and `json`) is executed on CI. (Recommended.)
- D4: Fix F2 by documenting the 17 codes. Fix F3 by either raising `LOOPSERV_ERR_CIRCUIT_BREAKER` where the breakers terminate a loop, or removing it. (Recommended: raise and record it, so callers get a code instead of free text.)
