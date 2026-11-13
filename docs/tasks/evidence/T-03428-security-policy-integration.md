# T-03428 Evidence: Tool Registry & Taxonomy — security policy Integration

- Date: 2026-11-13
- Spec: [T-03424-security-policy-specification.md](T-03424-security-policy-specification.md)
- Previous: [T-03426 implementation](T-03426-security-policy-implementation.md), [T-03427 unit tests](T-03427-security-policy-unit-test.md)

## Production call paths
| Surface | How it reaches the policy | Since |
|---|---|---|
| `_dispatch.dispatch()` (all PEP-gated MCP tools) | `evaluate(surface="dispatch")` + `grant_reason_suffix` | T-03426 |
| Agent loop (`agent_loop_policy._registry_irreversible`) | `evaluate(surface="agent_loop")` | T-03426 |
| MCP `aios_tool_registry_stats` | `data.policy_revision` | T-03426 |
| **MCP `aios_tool_registry_decide`** | **new `data.policy` block via `preview()`** | T-03428 |
| **CLI `aiosh-tool-registry decide`** (pyproject entry point) | **new `policy` block / `policy.*` lines via `preview()`** | T-03428 |

## What changed
- `tool_registry_policy._combine()` holds the single OR rule. `evaluate()` and the new `preview()` both call it, so the
  read-only preview cannot drift from what dispatch enforces.
- `preview(svc, decision, *, require_grant)` is pure: no report line, no failure announcement, no process state. It
  returns `policy_revision`, `enforced_requires_grant`, `enforced_irreversible`, `registry_added_grant` and
  `grant_reason_suffix`.
- MCP decide: its private service is rebuilt if the server's mode differs, so it can never report a stale mode.
- CLI human output flattens the block into `policy.*` lines.

Example:
```
$ aiosh-tool-registry decide aios.anchor.create --mode strict
  ...
  policy.policy_revision: trp-08e7355aa14ca9a9
  policy.enforced_requires_grant: True
  policy.registry_added_grant: True
  policy.grant_reason_suffix: ' (tool registry strict, catalog trp-08e7355aa14ca9a9)'
```

## Cross-substrate parity
The policy changes neither the shared SQLite audit schema nor canonical JSON. Refusals still write the same row, with the
same columns, as before T-03426. The Rust side keeps its own grant rule, pinned by `test_tool_registry_rust_drift.py`
(still passing). No parity change was needed.

## Tests
`tests/test_tool_registry_policy_integration.py` has 11 tests:
- The CLI preview suffix equals the real `dispatch()` refusal reason, for 4 tools in strict.
- MCP decide `policy` equals `evaluate()` in both modes.
- One revision across the policy, stats, MCP decide and the CLI.
- Shadow enforces nothing extra.
- A caller's grant is not attributed to the registry.
- `preview()` is pure.
- Human CLI output shows the policy.
```
$ python -m pytest tests/test_tool_registry_policy_integration.py -q
11 passed in 3.07s
```
Mutation (drop the caller's grant in `_combine`): `2 failed, 49 passed` across the unit and integration files. Reverted.

## Integration smoke / regression
```
$ python -m pytest tests/ -q -k "tool_registry or agent_loop or audit_chain_concurrency or grant_scope or secret_masking or dispatch or task_service or mcp_server_core"
1344 passed, 2 skipped, 774 deselected, 3 warnings in 266.94s
$ python tools/test_por_conformance_suites.py   ->  CONFORMANT: C1..C6 PASS
$ python tools/demo_por.py                      ->  PROVABLY_RESTRAINED; post-anchor tamper REJECTED
```

## Security audit (standing rule)
- **Read-only surfaces:** both decide surfaces stay read-only and token-free. `preview()` never writes audit rows, stderr
  report lines or process state (`test_preview_is_pure`). A caller cannot use it to fill the disagreement log or
  suppress a later real failure announcement.
- **No information leak:** the new fields are booleans, a fixed-text suffix and a hex digest of public catalog fields.
  The catalog itself is already exported by `aiosh-tool-registry export`.
- **No enforcement change:** dispatch and the agent loop compute exactly what they did before, now through the shared
  `_combine`. The 1344-test battery and PoR C1..C6 pass unchanged.
- **Stale-mode fix:** before, MCP decide could report the mode of its first call. It now follows the server's mode,
  closing a potential operator-misleading preview.
- **Injection:** the CLI's `--json` output stays escaped; tool names reach output only through the existing
  `_safe`/`_shown` paths. No new argv is parsed.
- **PoR (I-2):** gates and redeem-before-act are untouched. **No bypass.**
