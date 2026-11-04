# T-03284 Specification: Agent Loop Hardening — CLI surface

- Date: 2026-11-05
- Decisions adopted from T-03283: D1 (one-shot runner + audit-backed history), D2 (`complete_loop`), D3 (`python -m`), D4 (limits), D5 (stdlib only).
- Everything below is **AIOS-specific**. No upstream CLI is being mirrored.

## Invocation
```
python -m aiosh_mcp.agent_loop_cli <subcommand> [options] [--json]
```
Module: `code/aiosh-mcp/aiosh_mcp/agent_loop_cli.py` (new). Entry point: `main(argv) -> int`.

## Interfaces
| Status | Interface |
|---|---|
| Reused | `AgentLoopService.start_loop / advance_turn / abort_loop / get_snapshot` |
| Reused | `PepCapabilityGate`, `audit_client.open_db` (read-only query for history) |
| Reused | `LoopConfig.validate_bounds`, `mask_secrets` |
| **New** | `AgentLoopService.complete_loop(loop_id, capability_token) -> LoopSnapshot` (`OBSERVE -> COMPLETED`, audited `aios.agent_loop.complete`, token-bound like abort) |
| **New** | `load_plan(path) -> list[PlanTurn]`, `parse_cli_args(argv)`, `dispatch_cli(argv, service=None, db_path=None) -> CliResult`, `main(argv)` |

## Subcommands
| Subcommand | Kind | Arguments |
|---|---|---|
| `validate --plan FILE` | read-only, no token | Validates the plan file only |
| `run --loop-id ID --token GRANT --plan FILE [--max-iterations N] [--max-total-tokens N] [--total-timeout-ms MS] [--consecutive-failure-limit N]` | **mutating, token** | start, then each turn, then complete (or stop when the loop terminates) |
| `history --loop-id ID [--limit N]` | read-only, no token | Reads `aios.agent_loop.*` rows for `ID` from the audit ring, oldest first, `N` in [1, 1000], default 100 |

### Plan file (JSON)
```json
{"turns": [{"action_intent": "read README", "tool_name": "aios.fs.read",
            "tool_args": {"path": "README.md"}, "tokens_consumed": 120,
            "policy_allowed": true}]}
```
- File at most 1 MiB, UTF-8, top-level object with `turns`: a list of 1..100 objects.
- `action_intent` is a required string. `tool_name`, `tool_args` (object), `tokens_consumed` (default 0) and `policy_allowed` (default true) are optional. Unknown keys are rejected.
- The per-turn caps are the service caps (T-03280). They are checked in `validate`, before any grant is redeemed.

## Outputs
Human mode prints one line per turn plus a summary. `--json` prints exactly one JSON object to stdout:
```json
{"ok": true, "exit_code": 0, "subcommand": "run", "data": {...}}
{"ok": false, "exit_code": 3, "subcommand": "run", "error_code": "LOOPSERV_ERR_UNAUTHORIZED", "error": "..."}
```
`run` data: `loop_id`, `final_state`, `turns` (step dicts), `refused` count, `terminal_reason`.
`history` data: `loop_id`, `events` (`id, ts, tool, outcome, outcome_detail, args`).
`validate` data: `turns` count.
All output passes through `mask_secrets`.

## Exit codes (same taxonomy as `model_backend_adapters_cli`)
| Code | When |
|---|---|
| 0 | success. A `run` with refused steps still exits 0, because a refusal is a policy outcome, not a failure. |
| 1 | runtime failure (`LOOPSERV_ERR_AUDIT`, `GATE_UNAVAILABLE`, `CAPACITY`, `NOT_FOUND`, `TERMINATED`, I/O) |
| 2 | usage / invalid input (argparse errors, NUL byte in argv, bad plan file, `LOOPDATA_ERR_BOUNDS_EXCEEDED`, `LOOPSERV_ERR_INVALID_INPUT`) |
| 3 | `LOOPSERV_ERR_UNAUTHORIZED` (missing token, unredeemable grant) |
| 4 | `LOOPSERV_ERR_TIMEOUT` |

## Failure paths
- Invalid plan: exit 2 **before** redemption, so the grant is not consumed.
- Grant refused: exit 3, nothing registered (the redeem refusal writes no row; a successful redeem writes `pep.capability.redeem`).
- Loop terminates mid-plan (breaker, iteration ceiling): stop, exit 0, `final_state` FAILED, remaining turns not run (`turns_skipped` reported).
- Audit failure mid-run: exit 1. The loop is ABORTED by the service (T-03280).

## Persistence and audit effects
`run` writes exactly the service's rows: `pep.capability.redeem`, `aios.agent_loop.start`, one `aios.agent_loop.step` per
executed turn, then `aios.agent_loop.complete` (or nothing further if the loop self-terminated).
`validate` and `history` write nothing. DB path: `$AIOSH_HOME/audit.db` (`audit_client.default_db_path`).

## Invariants
- LOOPCLI-INV1: only `run` mutates, and it needs `--token` (PoR I-2).
- LOOPCLI-INV2: one JSON object on stdout in `--json` mode; exit code equals `exit_code` in the payload.
- LOOPCLI-INV3: plan validation completes before grant redemption.
- LOOPCLI-INV4: no secret reaches stdout or stderr unmasked.
