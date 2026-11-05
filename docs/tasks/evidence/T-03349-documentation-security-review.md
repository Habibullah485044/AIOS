# T-03349 Security Review: Agent Loop Hardening — documentation

- Date: 2026-11-05
- Scope: `agent_loop_doc.reference()` and its MCP (`aios_agent_loop_doc`) and CLI (`doc`) surfaces, plus the CI drift test that executes doc examples.
- Method: **my own review with targeted probes. No independent subagent this time:** the surface is read-only, takes one enum argument, and writes nothing.
  Earlier epics' independent reviews did find issues, so this review is the weaker kind and I say so.

## Findings
| # | Sev | Finding | Status |
|---|---|---|---|
| D1 | Low | **Cost amplification.** Each tokenless call rebuilt a FastMCP instance to read tool schemas: ~1.75 s cold, **~122 ms / ~3 MB warm** per call, on the shared worker pool. My first probe reported 377 ms, which mostly measured import cost; this is corrected here. | **Fixed:** the reference is built once per process (`lru_cache`; code cannot change at runtime) and callers get deep copies. A warm call now takes ~0.6 ms. |
| D2 | — | Cache poisoning: a caller mutating the returned dict. | Not possible: deep copies (tested). |
| D3 | — | Data exposure: env values, `AIOSH_HOME`, paths, grant ids. | Not present: only env variable **names** and defaults. Probes with sentinel `AIOSH_HOME` and `AIOSH_AGENT_LOOP_CONFIG` values found neither in the output, and no `gr_*` token-like strings. |
| D4 | — | Side effects: `reference()` registers tools on a throwaway FastMCP with `settings={}`. | Verified: no config resolution or degraded-audit write, the global service is untouched, and no audit DB is created (a sentinel home stays absent). |
| D5 | Accepted | The drift test **executes** the doc's `python` blocks in CI. | Same trust boundary as the tests themselves (repo-controlled, PR-reviewed), with a 120 s timeout, a temp `AIOSH_HOME`, and the package dir as cwd. |
| D6 | — | Input: `section` is a schema enum (MCP) or argparse `choices` (CLI); `reference()` also raises on unknown values. | Not exploitable. |

## Tests (`tests/test_agent_loop_doc_security.py`, 3)
| Test | Old code | New code |
|---|---|---|
| repeated calls are cheap (< 10 ms each when warm) | **fails** (~122 ms) | passes (~0.6 ms) |
| callers cannot poison the cache | passes (nothing was cached before) | passes |
| no side effects or secrets | passes | passes |
The first draft of the cost test used a 50 ms threshold and passed against the old code too. It was tightened to 10 ms so it actually separates old from new.

## PoR standing rule
No state-changing path. **No bypass.**
