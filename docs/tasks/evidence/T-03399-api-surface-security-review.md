# T-03399 Security Review: Tool Registry & Taxonomy — API surface

- Date: 2026-11-06
- Scope: `aios_tool_registry_decide` / `_stats`, and above all `apply_catalog_annotations`. It made **40 of 71** served tools advertise
  `readOnlyHint=true`, which some MCP clients auto-approve without a confirmation prompt.
- Method: an **independent read-only reviewer subagent** read the implementation of every read-only-advertised tool and probed each
  one empirically, comparing files, DB tables, grants and in-memory state before and after each call. I reproduced F1 and F2 myself
  (`aios_restraint_prove` was advertised read-only while taking `caller_grant_id`; the merge turned `destructiveHint=True` into read-only).

## Verdicts (reviewer)
- **33 tools are genuinely read-only:** audit tail/verify/segments/seen, anchor verify, MCP core status/list/ping/config/policy/
  observability/doc/test-run, model list/health/doc/observability, agent-loop reads, registry list/get/stats. They write at most the
  project's normal per-call audit rows.
- **2 are NOT read-only:** `aios_restraint_prove` and `aios_restraint_verify` redeem `caller_grant_id` (`UPDATE pep_grants SET redeemed_at`).
- **2 are file oracles:** `aios_mcp_recovery_check` and `aios_model_validate_config`.
- `aios_tool_registry_decide` changed server telemetry.

## Findings
| # | Sev | Finding | Status |
|---|---|---|---|
| F1 | **Medium** | **Grant burning via an auto-approvable tool.** A prompt-injected model could call `aios_restraint_prove(grant_id=X, caller_grant_id=X)` with no confirmation. That consumes a single-use grant X and destroys the very non-use proof the tool produces. | **Fixed twice over:** (1) the catalog now marks both restraint tools `additive`; (2) a structural rule: **no tool with a grant/token argument** (`grant_id`, `caller_grant_id`, `capability_token`, `token`, `*_grant_id`) is ever advertised read-only, whatever the catalog says. |
| F2 | Low | `more_cautious` turned an annotation with `readOnlyHint` unset but `destructiveHint=True` (or `idempotentHint=False`) into read-only. That breaks TOOLAPI-INV2. No served tool has this shape today. | **Fixed:** an explicit effect claim blocks read-only. |
| F3 | Low | `decide` fed the server's dispatch counters, so a caller could inflate disagreement counts or fill the 50 unregistered samples, hiding real dispatch misses. | **Fixed:** `decide` uses its own service instance (same catalog and mode); server stats count dispatch and agent-loop decisions only. |
| F4 | Low | Auto-approvable file oracles with no PEP check: `aios_mcp_recovery_check(path)`, `aios_model_validate_config(config_path)`, and `aios_restraint_prove(anchors_path)`, which also reveals resolved paths in its errors. | **Fixed for the annotation risk:** read-only is now granted only to entries with `scope_kind=none` **and** no path-like argument (`path`, `file`, `dir`, `*_path`, …), so these tools prompt again. **Follow-up (out of this epic's scope):** confine their path arguments to `$AIOSH_HOME` in the tools themselves. |
| S1 | Low (suspected) | A membership oracle on dispatch's unregistered names through `decide` + `stats`. | **Resolved by F3:** `decide` no longer touches the samples. |
| S2 | Low (suspected) | `aios_audit_verify(full=True)` / `aios_audit_seen(exact=True)` scan every segment synchronously, and they are auto-approvable. | **Follow-up:** bound or off-thread these server tools. Not part of the registry. |

Not found (reviewer): no read-only tool starts processes, makes network calls, rotates or compacts stores, creates anchors, changes config, or
registers models or tools; `decide` / `stats` output has no grant ids, targets or raw names.

## Effect
Advertised read-only tools went from **40 to 35**, all of them verified genuinely read-only.

## Regression tests (`code/aiosh-mcp/tests/test_tool_registry_api_security.py`, 9)
Result on pre-fix code: **9 of 9 fail.** On the fixed code: **9 passed**. Three earlier tests that pinned the old F3 behaviour now assert the fix
(decide leaves server stats unchanged).
```
$ python -m pytest tests/ -k tool_registry -q
404 passed, 1 skipped, 1437 deselected, 1 warning in 39.57s
```

## PoR standing rule
Annotations are client hints and never relax server enforcement (TOOLAPI-INV3). This review closes a client-side path to consuming
a single-use grant (I-2) without a human confirmation. **No bypass of the server's gates existed or exists.**
