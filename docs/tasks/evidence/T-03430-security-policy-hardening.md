# T-03430 Evidence: Tool Registry & Taxonomy — security policy Hardening

- Date: 2026-11-13
- Previous: [T-03429 security review](T-03429-security.md) (introduced `aiosh_mcp/capability_redeem.py`)

## What changed
| Ledger requirement | Change |
|---|---|
| Timeouts | `capability_redeem.DB_TIMEOUT_S = 5.0` bounds both the SQLite connect and the busy handler. A locked audit DB refuses the action within that bound instead of hanging. |
| Size caps | The token cap (512, NUL refused) is unchanged. **New:** `command` ≤ 1024 and `target` ≤ 4096 chars, and both must be strings. They are checked **before any DB access**, so an oversized request neither opens the DB nor spends the grant. |
| Bounded retries | No retry loop is added. The gate makes exactly one atomic redeem attempt (`UPDATE … WHERE redeemed_at IS NULL`), so a retry could only double-spend. |
| Errors in the standard envelope | `aiosh-tool-registry decide` now catches any failure in the service or policy and returns `TOOLCLI_ERR_UNAVAILABLE` with the exception type only, never its message text or a traceback. MCP `aios_tool_registry_decide` already returned `TOOLREG_ERR_UNAVAILABLE`, which is now pinned by a test. The capability gate always returns a reason string, never raises. |
| Resource cleanup | The gate's connection is opened under `contextlib.closing`. After a lock timeout the DB is not left locked, and the grant is intact (test). An audit-ring write failure rolls the redemption back, so the grant stays redeemable once (`grant_redeem`'s compensating `UPDATE`, test). |
| Fail-open writes an honest audit row (ADR-0035 F-2) | The policy never fails open on enforcement. Shadow mode is advisory by definition, and strict mode fails closed. The fail-closed refusal row is honest: `outcome_detail` carries `(tool registry unavailable, strict: fail closed)`, asserted against the real audit DB. |

## Tests
`tests/test_tool_registry_policy_hardening.py` has 9 tests. 3 failed before the changes: the CLI traceback, the
oversize command and target, and the missing timeout bound.
- CLI and MCP decide report a broken policy in the envelope.
- Oversized command and target are refused in under 1 s, and the grant is not spent.
- A locked DB refuses within the bound and releases the lock.
- An audit-write failure refuses and keeps the grant.
- **A single-use grant raced by 12 threads redeems exactly once, with exactly one audit row.**
- Failure announcements happen once per surface under 16-thread concurrency.
- A strict registry failure writes an honest refusal row.
```
$ python -m pytest tests/test_tool_registry_policy_hardening.py -q
9 passed in 3.44s
```

## Regression
```
$ python -m pytest tests/ -q -k "tool_registry or agent_loop or audit_chain_concurrency or grant_scope or secret_masking or dispatch or model_backend or mcp_server_core or capability or task_service"
16 failed, 1629 passed, 2 skipped   -> all 16 are tests/test_capability_*_smoke.py FileNotFoundError
                                       (missing Rust debug binary; part of the known 136 baseline), 0 other
$ python tools/test_por_conformance_suites.py   ->  CONFORMANT: C1..C6 PASS
$ python tools/demo_por.py                      ->  PROVABLY_RESTRAINED
```

## Security audit (standing rule)
- **DoS:** an attacker-sized `target` or `command` can no longer reach SQLite or the audit row. A held DB lock costs a
  caller at most `DB_TIMEOUT_S`, and the action is refused, not run.
- **Double spend:** concurrency is pinned at 12 threads. Exactly one redemption succeeds, so a single-use grant cannot
  authorise two state changes.
- **Information leak:** CLI errors name the exception type only, so no paths or messages reach the terminal. Gate
  reasons are secret-masked and capped at 300 chars (T-03429).
- **Honest audit:** the only degraded path (strict mode, registry down) refuses, and says why in the row.
- **PoR (I-2):** redeem-before-act is unchanged; the gate only refuses more (bad sizes, timeouts). **No bypass.**
