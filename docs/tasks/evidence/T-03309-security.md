# T-03309 Security Review: Agent Loop Hardening — configuration

- Date: 2026-11-05
- Scope: `aiosh_mcp/agent_loop_config.py` and its consumers wired in T-03308 (service capacity, gate busy timeout,
  MCP settings plus the `aios_agent_loop_config` tool, CLI `config` and `run` defaults).
- Method: my own review plus an **independent subagent review** that saw the code, not my conclusions. The independent
  review found both HIGH issues; I had found neither. Every finding was reproduced before it was fixed.

## Findings
| # | Severity | Finding | Fix |
|---|---|---|---|
| S1 | **HIGH** | `resolve()` raised on a 400-digit JSON integer (`OverflowError` from `float()`) or one over 4300 digits (`ValueError` from `json.loads`). The server resolves config **at import** (`_GLOBAL_AGENT_LOOP_SERVICE`), so a hostile `AIOSH_AGENT_LOOP_CONFIG` file, or a `./docs/agent_loop_config.json` in an untrusted CWD, **crashed the MCP server at startup**. | `_number` maps overflow to a value error; `_read_file` catches `ValueError`; `resolve()` gained a catch-all that falls back to defaults (AGENTLOOPCONF-INV1 now holds by construction) |
| S2 | **HIGH** | `AIOSH_AGENT_LOOP_CONFIG=CON` passed `hygiene_ok`, and `open().read()` **hung forever** at import. By code reading the same applies to a FIFO, `/dev/stdin` (it would consume the stdio MCP stream) and UNC paths (SMB stall, NTLM hash leak). | `hygiene_ok` and `_read_file` reject UNC/`\.\` device namespaces and Windows device names; only `S_ISREG` files are read; open with `O_NONBLOCK` and re-check with `fstat` after open |
| S3 | LOW-MED | `db_busy_timeout_ms` (up to 30 s) could exceed `mcp_call_timeout_s` (down to 1 s). A mutating MCP call would then report "outcome unknown" while its thread could still redeem a grant or commit. | The busy wait is clamped to at most half the call bound, and the adjustment is reported |
| S4 | LOW | The token-less `aios_agent_loop_config` tool returned unmasked error text: absolute paths, OSError text, the first 32 characters of a misplaced secret, and inputs echoed at about 60 KB. | Error values are no longer echoed, messages use the file basename only, and errors are `mask_secrets` + truncated to 300 characters |
| S5 | LOW | Misleading labels: a rejected env value relabelled the key `env_invalid` while the file value was in effect; `settings=` showed as `argument`; CLI `config --config X` previewed a file that `run` never used. | `source` is now always the level actually in effect, with rejections in a new `rejected` map; `settings=` is labelled `settings`; `run` accepts `--config` |
| — | held up | Locked keys cannot be expressed. Audit failure fails closed. NaN/inf/bool/64 KiB cap/deep nesting/BOM are handled. Clamped values pass `LoopConfig.validate_bounds`. | — |

## Abuse scenarios -> tests (`tests/test_agent_loop_config_security.py`: 18 pass, 1 skipped (FIFO, POSIX only))
S1: 400- and 5000-digit integers in a file; a 10**400 override. S2: `CON`, `nul`, `COM1.json`, `conin$`, `\.\pipe\aios`,
`\attacker\share\c.json`, `//attacker/share/c.json` via env (each in a **subprocess with a 20 s timeout**, so a hang fails the test);
explicit `CON`, UNC and directory paths; a FIFO; and **`import aiosh_mcp.server` with a hostile config file**. S3: busy/call coupling.
S4: no secret prefix, no private directory name, every error <= 300 characters. S5: truthful labels. Locked keys are still unrepresentable.

**Fails when broken:** with the old `agent_loop_config.py`, the 400-/5000-digit, `CON` (timed out = hang) and server-import tests fail (4 failed).

## PEP / audit (PoR standing rule)
Configuration adds no state-changing path and cannot loosen grant redemption, audit writes or input/args caps (locked keys).
The worst a hostile config can now do is pick in-range tunables, which are bounded and reported. **No known bypass remains open.**
