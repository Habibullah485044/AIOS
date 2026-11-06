# T-03410 Evidence: Tool Registry & Taxonomy — configuration Hardening

- Date: 2026-11-06
- Scope: failure modes left after the T-03409 review. That review fixed fail-open paths, path leaks and consumer disagreement.
  This task is about visibility and isolation.

## Gaps found (probe) and fixed
| Failure mode | Before | After |
|---|---|---|
| **A rejected config silently forces strict** | a config file with an unknown key → service in `strict` and **0 stderr lines** (probe). The operator sees unexplained refusals; the reason is only in the token-free stats tool | `process_config()` announces problems **once** on stderr: count, resulting mode, and up to 10 `repr`-escaped, bounded error lines. Never stdout (the MCP JSON-RPC channel), never an audit row, and a closed stderr is ignored. A clean config prints nothing |
| **The default config location cannot be computed** (e.g. `$AIOSH_HOME` broken) | the exception escaped to the catch-all: whole resolution replaced by defaults + strict, **valid env values discarded** (probe: `resolution failed (OSError)`) | isolated in `_file()`: `TOOLREGCONF_ERR_IO` "default config location unavailable", mode strict (cannot tell what the file would say), **env and argument values still apply** |

Error envelope: every problem has a `TOOLREGCONF_ERR_*` code, in `resolve()["errors"]`, in stats (codes only) and once on stderr.
Cleanup: no resources held (single bounded read, fd closed in `finally`).
Retries and timeouts: not applicable. Non-blocking open; FIFOs and devices are refused (T-03309/T-03409).

## Tests (`code/aiosh-mcp/tests/test_tool_registry_config_hardening.py`, 4)
| Test | Old code | New code |
|---|---|---|
| problems announced once on stderr (not stdout) | **fails** | passes |
| a clean config is silent | passes | passes |
| announcement survives a closed stderr | passes | passes |
| a default-path failure keeps env values | **fails** | passes |
```
$ python -m pytest tests/ -k tool_registry_config -q
82 passed, 1859 deselected, 1 warning in 36.03s
```
