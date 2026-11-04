# T-03283 Research: Agent Loop Hardening — CLI surface

- Date: 2026-11-05
- Scope: research only. **No code changed.**

## Facts (verified in this repo)
| # | Fact | Source |
|---|---|---|
| F1 | Loop state lives **only in process memory** (`AgentLoopService._loops`). A loop started by one CLI process does not exist in the next. | `code/aiosh-mcp/aiosh_mcp/agent_loop_service.py` |
| F2 | The **durable** record of a loop is the hash-chained `audit_ring`. Rows `aios.agent_loop.{start,step,abort,timeout}` carry `loop_id` in `args_json`. | `agent_loop_gate.py` (T-03279), `audit_client.write_audit_row` |
| F3 | Starting a loop redeems a **single-use** PEP grant, and later calls must present the same grant id. | T-03279 evidence |
| F4 | Grants are issued only by the TS CLI: `aiosh grant create --to <subject> --tools <globs> [--ttl s]`. | `code/aiosh-cli/src/cli.ts:714-752` |
| F5 | The precedent for Python CLI surfaces is a stdlib module with `parse_*_cli_args` / `dispatch_*_cli` / `main(argv)`, run via `python -m`. It rejects NUL bytes, has a `--json` mode, and uses exit codes 0 ok / 1 failure / 2 usage / 3 unauthorized / 4 timeout. | `aiosh_mcp/model_backend_adapters_cli.py:40-46,80-86,296` |
| F6 | No Python CLI is registered as a console script (`pyproject.toml` has no `[project.scripts]`), and none is wired into the TS `aiosh` binary. | `code/aiosh-mcp/pyproject.toml` |
| F7 | The SQLite available here is 3.50.4 with JSON1 (`json_extract` works). | local check |
| F8 | The service has no "complete" operation. `OBSERVE -> COMPLETED` is a legal FSM edge, but only `abort_loop` can end a loop. | `agent_loop_data_model.VALID_TRANSITIONS` |

## Upstream references
- Python `argparse` (stdlib): sub-commands via `add_subparsers`, and exit status 2 on usage errors — https://docs.python.org/3/library/argparse.html
- `sqlite3` JSON1 `json_extract` — https://sqlite.org/json1.html
- Exit status conventions: 0 success, 2 for usage errors (argparse default; also BSD `sysexits.h` `EX_USAGE` = 64, not used here to stay consistent with F5).

## Assumptions (not verified)
- A1: Operators want to drive a whole loop from a file of planned turns (a dry run through the policy gate) more than they want interactive per-turn commands. Interactive use needs a long-lived process, which is the MCP server.
- A2: Audit-ring reads are cheap enough for `history`, with a hard row cap.

## Consequences for design
Because of F1, per-turn subcommands (`start`, then `advance` in a separate invocation) **cannot work** without a
persistence layer. Two honest options:
1. **One-shot runner**: `run --plan FILE` does start, every turn and finish in **one process** (state never needs to survive).
2. **Read from the durable record**: `history <loop_id>` reconstructs events from the audit ring (F2).

## Decisions needed (for T-03284)
- D1: Adopt the one-shot runner plus audit-backed history? (Recommended. Defer persistence to a later epic.)
- D2: Add `AgentLoopService.complete_loop` (`OBSERVE -> COMPLETED`, audited) so a finished plan ends COMPLETED, not ABORTED. (Recommended. Small, audited, token-bound.)
- D3: Keep the module-runner precedent (`python -m aiosh_mcp.agent_loop_cli`) and add no console script or TS wiring now. (Recommended, per F5/F6.)
- D4: Plan file limits: a size cap (1 MiB proposed), at most 100 turns (the `max_iterations` ceiling), and the same per-turn caps as the service.
- D5: No new dependencies. Only stdlib `argparse`, `json`, `sqlite3`.
