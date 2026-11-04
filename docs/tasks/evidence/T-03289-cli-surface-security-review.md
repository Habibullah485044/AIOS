# T-03289 Security Review: Agent Loop Hardening — CLI surface

- Date: 2026-11-05
- Scope: `code/aiosh-mcp/aiosh_mcp/agent_loop_cli.py` (T-03286..T-03288)

## Findings
| # | Severity | Finding | Status |
|---|---|---|---|
| C1 | **Medium** (CWE-214) | `--token GRANT` puts the single-use grant id in the process list and shell history. A local observer could redeem it first and start their own loop within that grant's scope. | **Fixed**: new mutually exclusive `--token-env VAR` and `--token-stdin`. Docs will recommend these; `--token` is kept for compatibility. |
| C2 | Low | No length bound on the token value | **Fixed**: max 256 chars, longer is exit 2 |
| C3 | — | Forged token | Not vulnerable: redemption goes through `PepCapabilityGate` (T-03279); exit 3 and no audit rows |
| C4 | Low (CWE-367) | `load_plan` checked `stat().st_size` and then read the whole file. A file that grows in between is read unbounded. | **Fixed**: one bounded read of at most 1 MiB + 1 byte |
| C5 | Low | Deeply nested JSON raised `RecursionError` into the catch-all (exit 1, "internal") | **Fixed**: now reported as a plan error, exit 2 |
| C6 | — | Directories, devices or FIFOs as plan path | Not vulnerable: `is_file()` rejects them (exit 2) |
| C7 | — | Terminal-escape injection (CWE-150) and secret leaks via tool args | Not vulnerable: human output prints only validated fields (`tool_name` regex, outcome, refusal reason); JSON escapes control chars; everything is masked |
| C8 | — | SQL injection via `history --loop-id` | Not vulnerable: parameterised query, read-only URI |
| C9 | Accepted | `history` needs no token | By design (read-only, spec). Anyone who can read `audit.db` can already read these rows, so file permissions on `$AIOSH_HOME` are the boundary. |

## Abuse scenarios -> tests (`tests/test_agent_loop_cli_security.py`, 11 cases)
C1: env token, stdin token, unset env var (exit 3, no rows), exclusive sources. C2: 257-char token.
C3: forged token. C4: oversized content bounded. C5: 200k `[`. C6: directory as plan.
C7: ESC/BEL and `Bearer sk-...` in tool args, absent from run/history output in both modes. C8: `x' OR '1'='1`.

## PEP gating and audit (PoR I-2 standing rule)
`run` is the only state-changing path. It cannot execute without redeeming a grant through
`PepCapabilityGate.redeem`, and plan and config validation happen before redemption (LOOPCLI-INV3).
Each consequential event writes exactly one audit row (start, step, complete). `validate` and `history` write nothing.
**No known policy bypass remains open.**

## Verification
```
cd code/aiosh-mcp && python -m pytest tests/ -k agent_loop -q
140 passed, 909 deselected in 8.29s
```
