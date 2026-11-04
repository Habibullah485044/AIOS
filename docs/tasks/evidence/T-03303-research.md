# T-03303 Research: Agent Loop Hardening — configuration

- Date: 2026-11-05
- Scope: research only. **No code changed.**

## Facts: every agent-loop tunable is a hard-coded constant today
| Constant | Value | Location | Nature |
|---|---|---|---|
| `LoopConfig` defaults: `max_iterations`, `max_total_tokens`, `timeout_ms_per_step`, `total_timeout_ms`, `consecutive_failure_limit` | 25, 32768, 30000, 300000, 3 | `agent_loop_data_model.py:107-111` | per-loop **defaults**; bounds enforced by `validate_bounds` |
| Registry capacity | 256 | `agent_loop_data_model.py:26`, used `agent_loop_service.py:84` | resource cap |
| SQLite `busy_timeout` | 5000 ms | `agent_loop_gate.py:24` | wait bound |
| History read timeout | 5.0 s | `agent_loop_gate.py:26` | wait bound |
| MCP per-call timeout | 15.0 s | `agent_loop_mcp.py:36` | wait bound |
| History page budget | 1 MiB | `agent_loop_mcp.py:38` | response cap |
| Snapshot step tail default | 100 | `agent_loop_mcp.py:39` | response default |
| `MAX_ARGS_SUMMARY_BYTES` / `MAX_TOOL_ARGS_DEPTH` | 64 KiB / 32 | `agent_loop_data_model.py:24`, `agent_loop_service.py:55` | **audit fidelity** (T-03299) |
| `MAX_ACTION_INTENT_CHARS`, `MAX_REASON_CHARS`, `MAX_TOKENS_PER_TURN`, `TOOL_NAME_PATTERN` | 4096, 1024, 1e6, regex | `agent_loop_service.py:52-56` | input validation |
| CLI plan / history / token caps | 1 MiB, 100 turns, 1000, 256 | `agent_loop_cli.py:45-49` | input validation |
| Audit DB location | `$AIOSH_HOME/audit.db` | `audit_client.default_db_path` | shared with every subsystem |

## Facts: repo precedent for configuration modules
`aiosh_mcp/compliance_config.py` (T-02903..T-02907) and `runbook_config.py` define the house pattern:
- Precedence: **argument -> env -> config file -> default**, resolved into `{"config": ..., "source": {key: origin}}` (`compliance_config.py:227`).
- Env names use `AIOSH_<SUBSYSTEM>_*` (`AIOSH_COMPLIANCE_CONFIG`, `AIOSH_RUNBOOK_STEP_TIMEOUT`).
- The config file is capped at 64 KiB (CWE-400) and is a JSON object.
- Env-supplied paths pass a CWE-15 hygiene predicate (non-empty, no `..`, no control chars, <= 1024); an invalid value is **rejected and reported** (`env_invalid`), never applied.
- Inert numeric fields **clamp** to their bounds. Security-relevant settings **cannot be disabled by config** (e.g. `audit_all_mutations` forced `True`).

## Upstream references
- CWE-15 External Control of System or Configuration Setting: https://cwe.mitre.org/data/definitions/15.html
- CWE-400 Uncontrolled Resource Consumption: https://cwe.mitre.org/data/definitions/400.html
- Python `os.environ` (read at call time, so tests can monkeypatch): https://docs.python.org/3/library/os.html#os.environ

## Assumptions
- A1: Operators mainly need to tune per-loop default budgets and the wait bounds for slow disks. Nobody needs to loosen input or audit caps.
- A2: Resolving config once per service or MCP registration is enough. No hot reload is needed.

## Decisions needed (for T-03304)
- D1: **Configurable** (clamped to bounds): the 5 `LoopConfig` defaults (within `validate_bounds` ranges), registry capacity (1..256),
  MCP call timeout (1..60 s), history page budget (64 KiB..4 MiB), snapshot tail default (0..1000), busy timeout (100..30000 ms).
- D2: **Not configurable** (security or audit fidelity): grant redemption and loop binding, audit writes, the args cap and depth (T-03299),
  input-length caps, the tool-name pattern, the token length cap. Config keys naming them are rejected as unknown keys, not silently ignored.
- D3: Env names `AIOSH_AGENT_LOOP_CONFIG` (file path) plus one `AIOSH_AGENT_LOOP_<FIELD>` per tunable. Default file
  `docs/agent_loop_config.json` (optional; absence means defaults).
- D4: A config file over 64 KiB, unparsable, or not an object: **fail closed to defaults** and report `config_invalid` in `source`.
  The loader never raises into the server's import path.
- D5: Expose the resolved config read-only (`aios_agent_loop_config` MCP tool and `agent_loop_cli config`) for operators. Decide in the spec.
