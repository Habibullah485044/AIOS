# T-03409 Security Review: Tool Registry & Taxonomy — configuration

- Date: 2026-11-06
- Scope: `aiosh_mcp/tool_registry_config.py`, its consumers (`tool_registry_service.py`, `tool_registry_api.py`), and the shared
  path guard `agent_loop_config._special_path_reason` / `hygiene_ok`, which also protects the agent-loop config file.
- Method: an **independent read-only reviewer subagent** was given the code and spec only, and probed on Windows 10 / Python 3.14.
  I reproduced #1, #2, #7 and #10 myself before fixing:
  - `\??\UNC\127.0.0.1\C$\…` passed `hygiene_ok`;
  - a BOM file saying strict resolved to shadow;
  - `{"mode":"strict","mode":"shadow"}` resolved to shadow with no error;
  - `CON .json` and `nul:` passed `hygiene_ok`.

  Every fix has a regression test, run against the pre-fix code.

## Findings
| # | Sev | Finding | Status |
|---|---|---|---|
| 1 | **Medium** | **SMB/NTLM leak through the shared path guard.** `\??\UNC\host\share\…` (NT object-manager prefix) passed `hygiene_ok`, and Windows opened it over SMB. The same guard protects the agent-loop config. | **Fixed:** `/??/` and `??/` prefixes refused. A path whose `realpath` resolves to a network or device location is refused too (covers links and junctions). |
| 2 | **Medium** | **A rejected file threw away its own `strict`.** UTF-8 BOM (PowerShell `-Encoding utf8`), UTF-16 (PowerShell `>`), a typo key, a non-string mode, oversize: each made the whole file ignored, so the mode fell to shadow. That conflicts with INV1. | **Fixed:** a configured file that cannot be used **counts as asking for strict** (numbers fall back to defaults). A UTF-8 BOM is now accepted. |
| 3 | Low-Med | An env path that is missing, empty or rejected hid the default file, so the mode could drop to shadow. | **Fixed:** an unusable env path counts as strict. An empty env value means "not set". |
| 4 | **Medium** | **Consumers disagreed.** The service and `intended_mode()` re-resolved; `report()` and stats used the cached value. Stats could show a mode other than the one enforced, and a file read twice was a small TOCTOU. | **Fixed:** every consumer reads the one per-process `process_config()` (spec §3). |
| 5 | Low-Med | The default file was CWD-relative, and the CWD is chosen by the MCP client. The fail-closed fallback re-read it on every call, so deleting the file or changing directory could turn strict into shadow. | **Fixed:** the default file is `$AIOSH_HOME/tool_registry_config.json`, and it is resolved once per process. |
| 6 | Low | `report_max_lines=0` switched off the disagreement log. | **Fixed:** the minimum is 1. `unregistered_samples=0` stays allowed (it is telemetry only). |
| 7 | Low | Duplicate JSON keys were silently accepted, last one wins. A reviewer reads the first. | **Fixed:** duplicates give `TOOLREGCONF_ERR_PARSE`; the file is ignored and counts as strict. |
| 8 | Low | The internal-failure fallback ignored the argument and file modes. | **Fixed:** the fallback is strict. |
| 9 | Low | The token-free stats tool exposed error *messages*: config basename, key names from whatever file the env points at, OS text. | **Fixed:** stats exposes the sorted error **codes** only. |
| 10 | Info | `CON .json`, `NUL .json` and `nul:` passed the device check (still stopped later by the regular-file check). | **Fixed:** device names with trailing space, dot or colon are refused up front. |

Fine (reviewer):
- deep JSON, huge numbers, bools and floats are rejected cleanly; the read is capped and bounded;
- FIFO and device swaps are caught by `fstat`; the `\\?\`, `//` and mixed-slash UNC forms are refused;
- nothing is written; locked keys cannot be set by any channel;
- unknown mode values fail closed; error strings use `repr` and are bounded.

## Tests
- New `code/aiosh-mcp/tests/test_tool_registry_config_security.py` (22). **Pre-fix code: 20 failed, 2 passed**. The two that passed:
  `hygiene_ok("aux.")` and `"COM1 "` were already refused. Fixed code: 22 passed.
- New `code/aiosh-mcp/tests/conftest.py`: resets the per-process config around every test. Tests change env vars, and the config is
  now resolved once per process.
- Existing tests that pinned pre-review behaviour were updated:
  - `report_max_lines` minimum 1;
  - default file under `$AIOSH_HOME`;
  - fallback strict;
  - a locked-key file counts as strict;
  - two tests reset the cached config after changing env.

## PoR standing rule
Configuration can still only *raise* enforcement (strict adds grant requirements and irreversibility). This review closed every
channel by which a malformed, unreadable, relocated or ambiguous config could silently *lower* a requested strict mode, and an SMB
credential leak in the shared path guard. **No bypass.**
