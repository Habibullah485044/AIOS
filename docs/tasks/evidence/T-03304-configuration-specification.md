# T-03304 Specification: Agent Loop Hardening — configuration

- Date: 2026-11-05
- Adopts T-03303 D1..D5. It follows the `compliance_config.py` house pattern; every name below is **AIOS-specific**.

## 1. Module
New `code/aiosh-mcp/aiosh_mcp/agent_loop_config.py` (stdlib only). Public API:

| Function | Contract |
|---|---|
| `default_config() -> dict` | Fresh dict of the defaults below |
| `hygiene_ok(value) -> bool` | Total CWE-15 predicate for env-supplied paths: non-empty, no `..`, no control chars, <= 1024 chars. Never raises |
| `validate(config: dict \| None) -> dict` | Merges onto defaults and clamps every numeric field to its bounds. Unknown or locked keys raise `ValueError(AGENTLOOPCONF_ERR_UNKNOWN_KEY)` |
| `resolve(arg_config: str \| None = None, overrides: dict \| None = None) -> {"config", "source"}` | Full precedence ladder (§3). **Never raises** |
| `loop_config_for(loop_id, resolved=None, **explicit) -> LoopConfig` | `LoopConfig` from resolved defaults plus explicit per-call values (explicit wins) |

## 2. Fields
| Key | Default | Bounds (clamp) | Env override |
|---|---|---|---|
| `default_max_iterations` | 25 | 1..100 | `AIOSH_AGENT_LOOP_MAX_ITERATIONS` |
| `default_max_total_tokens` | 32768 | 100..1000000 | `AIOSH_AGENT_LOOP_MAX_TOTAL_TOKENS` |
| `default_timeout_ms_per_step` | 30000.0 | 1000..120000 | `AIOSH_AGENT_LOOP_TIMEOUT_MS_PER_STEP` |
| `default_total_timeout_ms` | 300000.0 | 5000..1800000 | `AIOSH_AGENT_LOOP_TOTAL_TIMEOUT_MS` |
| `default_consecutive_failure_limit` | 3 | 1..10 | `AIOSH_AGENT_LOOP_CONSECUTIVE_FAILURE_LIMIT` |
| `registry_capacity` | 256 | 1..256 | `AIOSH_AGENT_LOOP_REGISTRY_CAPACITY` |
| `mcp_call_timeout_s` | 15.0 | 1..60 | `AIOSH_AGENT_LOOP_MCP_CALL_TIMEOUT_S` |
| `history_page_bytes` | 1048576 | 65536..4194304 | `AIOSH_AGENT_LOOP_HISTORY_PAGE_BYTES` |
| `snapshot_steps_tail` | 100 | 0..1000 | `AIOSH_AGENT_LOOP_SNAPSHOT_STEPS_TAIL` |
| `db_busy_timeout_ms` | 5000 | 100..30000 | `AIOSH_AGENT_LOOP_DB_BUSY_TIMEOUT_MS` |

**Locked (never configurable):** `max_args_bytes`, `max_args_depth`, `max_action_intent_chars`, `max_reason_chars`,
`max_tokens_per_turn`, `tool_name_pattern`, `max_token_chars`, `require_grant`, `audit_mutations`.
A file key with one of these names is rejected (`AGENTLOOPCONF_ERR_LOCKED`). That way an operator who tries to loosen
a security control finds out, instead of believing it worked.

## 3. Precedence (strongest first)
1. `overrides` argument (explicit caller values)
2. per-field env `AIOSH_AGENT_LOOP_<FIELD>`. A non-numeric value is **rejected**, reported as `env_invalid`, and the lower level is kept.
3. config file: `arg_config`, else `AIOSH_AGENT_LOOP_CONFIG` (must pass `hygiene_ok`, else `env_invalid`), else `docs/agent_loop_config.json` if present
4. defaults (§2)

Then every value is clamped. `source[key]` is one of `argument | env | file | default | env_invalid | config_invalid`.

## 4. Failure behaviour (fail closed to defaults, never crash the server)
| Case | Result |
|---|---|
| File > 64 KiB, unreadable, invalid JSON, or not an object | file ignored; every field keeps its env/default value; `source["_file"] = "config_invalid"`, and `errors` lists `AGENTLOOPCONF_ERR_FILE_SIZE` / `_IO` / `_PARSE` |
| Unknown or locked key in the file | the whole file is ignored (`config_invalid`); error code `AGENTLOOPCONF_ERR_UNKNOWN_KEY` / `_LOCKED` |
| Out-of-range value | clamped; `source` keeps its origin; the clamp is noted in `errors` as `AGENTLOOPCONF_ERR_BOUNDS` |
| Bad env path for `AIOSH_AGENT_LOOP_CONFIG` | path not used; `source["_file"] = "env_invalid"` |

`resolve()` returns `{"config": {...}, "source": {...}, "errors": [...]}`. It never raises.

## 5. Persistence and audit effects
The module itself reads only. It writes no files and no audit rows (configuration is not a consequential action).
The resolved config **cannot** disable grant redemption or audit writes (locked keys).

## 6. Consumers (wired in the Integration task, not in scaffold or implementation)
`AgentLoopService(capacity=...)`, `PepCapabilityGate` busy timeout, the `agent_loop_mcp` timeout / page budget / tail default,
the `LoopConfig` defaults used by the MCP `start` tool and CLI `run`, plus a read-only exposure (`aios_agent_loop_config` and `agent_loop_cli config`).

## 7. Invariants
- AGENTLOOPCONF-INV1: `resolve()` is total. Any input yields a valid, in-bounds config.
- AGENTLOOPCONF-INV2: locked controls are not representable in config.
- AGENTLOOPCONF-INV3: every resolved value has a recorded `source`.
- AGENTLOOPCONF-INV4: an invalid env or file value is reported, never silently applied.
