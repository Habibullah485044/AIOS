# T-03344 Specification: Agent Loop Hardening — documentation

- Date: 2026-11-05
- Adopts T-03343 D1..D4. Everything is **AIOS-specific**. Stdlib only.

## 1. Generated reference (`aiosh_mcp/agent_loop_doc.py`)
`reference(section: Optional[str] = None) -> dict`. It is built **only from code**, at call time:
| Section | Content (source of truth) |
|---|---|
| `tools` | name, description (docstring), annotations, `inputSchema`: from a FastMCP instance with the agent-loop tools registered |
| `errors` | every `*_ERR_*` constant in `aiosh_mcp/agent_loop_*.py`, with its module and a one-line meaning (`ERROR_MEANINGS`, a table checked for completeness) |
| `config` | `agent_loop_config.FIELDS` (key, default, lo, hi, type, env) plus `LOCKED_KEYS` |
| `cli` | subcommand names and flags, from the argparse parser in `agent_loop_cli` |
| `policy` | the P1..P4 order and the irreversible name set, from `agent_loop_policy` constants |

An unknown `section` raises `ValueError` (MCP: a schema enum, so invalid values are tool errors; CLI: exit 2).

## 2. Surfaces
- MCP `aios_agent_loop_doc(section: Literal["tools","errors","config","cli","policy"] | None)`, `readOnlyHint`, no token.
- CLI `python -m aiosh_mcp.agent_loop_cli doc [--section S] [--json]`. The human form is a compact table per section.

## 3. Drift test (`tests/test_agent_loop_doc_drift.py`, in the CI battery through `-k agent_loop`)
1. Every error code, tool name, config key, locked key and CLI subcommand in `reference()` appears in `docs/SPEC-AGENT-LOOP-HARDENING-CORE-SERVICE.md`.
2. Every `ERR_*` constant has an `ERROR_MEANINGS` entry, and every entry names an existing constant.
3. The doc's ```python``` blocks are executed in a temp `AIOSH_HOME` and must succeed. ```json``` `tools/call` blocks must name existing tools and validate against their published schemas.

## 4. Fixes adopted
- Document the 17 missing codes (F2) in spec §6.
- `LOOPSERV_ERR_CIRCUIT_BREAKER` (F3): when a breaker (consecutive failures, token budget, iteration ceiling) terminates a loop during `advance_turn`,
  the step is returned normally. The snapshot's `terminal_reason` is prefixed `LOOPSERV_ERR_CIRCUIT_BREAKER: `, so callers can match a code.
  The data-model wording after the prefix stays the same.

## 5. Effects
Read-only. No audit rows. The generated reference never includes grant ids, DB paths or environment values (only env variable **names**).

## 6. Invariants
- LOOPDOC-INV1: every public identifier in code (codes, tools, config keys, CLI subcommands) is in the spec doc. CI fails otherwise.
- LOOPDOC-INV2: the reference is derived from code at call time; no hand-copied lists.
- LOOPDOC-INV3: every runnable doc example is executed in CI.
