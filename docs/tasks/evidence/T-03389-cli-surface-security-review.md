# T-03389 Security Review: Tool Registry & Taxonomy — CLI surface

- Date: 2026-11-06
- Scope: `aiosh_mcp/tool_registry_cli.py` (`aiosh-tool-registry`) and the shared `_shown` sanitiser in `tool_registry_data_model.py`.
- Method: an **independent read-only reviewer subagent** was given the code and spec only, and probed on Windows 10 / Python 3.14.
  I reproduced #1, #2 and #3 myself before fixing (`export | true` → rc 120 + traceback; `check 漢字 | cat` → UnicodeEncodeError, rc 1;
  `list $'\x1b]0;PWNED\x07'` → a raw ESC byte on stderr). Every fix has a regression test, run against the pre-fix code.

## Findings
| # | Sev | Finding | Status |
|---|---|---|---|
| 1 | **Medium** | **A closed pipe crashed on Windows.** Windows reports it as `OSError(EINVAL)`, not `BrokenPipeError`, so `export \| true` gave a traceback and **rc 120**. | **Fixed:** `_emit()` treats any OSError/ValueError on write as "reader gone", stops quietly, points fd 1 at devnull (no exit-time flush error), and keeps the real exit code. |
| 2 | **Medium** | **Non-cp1252 text on redirected stdout crashed** (UnicodeEncodeError, rc 1), even *after* a successful `export --out` (file written, exit 1). | **Fixed:** human output goes through `_safe()`: printable ASCII is kept and everything else is `unicode_escape`d, so it encodes on any stream. |
| 3 | **Medium** | **Usage errors echoed raw argv** (argparse's "unrecognized arguments"), so ESC/OSC/BEL reached the terminal (window title, screen clear). | **Fixed:** usage messages are escaped through `_safe()` and bounded to 400 chars. |
| 4 | Medium | With no `sys.stdout` (pythonw, closed fd 1) the run crashed with AttributeError. | **Fixed:** `_emit()` treats `None` as gone. |
| 5 | Low | `_shown` missed C1 controls (incl. CSI U+009B, NEL), U+2028/2029 and LRM/RLM/ALM. | **Fixed** in the shared `_FORBIDDEN_TEXT`. Human CLI output is now ASCII-escaped anyway. |
| 6 | Low | `export --out ""` silently dumped to stdout and exited 0. | **Fixed:** usage error (exit 2). |
| 7 | Low | `main` checked the raw argv for `"--json"`: abbreviations (`--js`) gave human output, and a *name* `--json` after `--` switched to JSON. | **Fixed:** `CliResult.as_json` carries argparse's own value. |
| 8 | Low | Exit-1 errors (`TOOLCLI_ERR_IO` / `UNAVAILABLE`) were printed to **stdout**, so `export > catalog.json` could write the error into the data file. | **Fixed:** every error goes to stderr in human mode; `--json` keeps the machine envelope on stdout. |
| 9 | Low | Export replaces the target's security descriptor: Windows explicit ACEs are lost; POSIX would get mkstemp's 0600. Any writable regular file can be replaced. | **Partly fixed:** the replaced file's POSIX mode is copied onto the new file. Windows ACL preservation and "replace any writable file" are **documented** (the operator chose the path, as with any `> file`). |
| 10 | Low | An interrupt between `mkstemp` and the `try` left a temp file. | **Fixed:** mkstemp is inside the `try`. While testing this I found a **further leak**: if `os.fdopen` fails, the raw fd stayed open and Windows could not delete the temp file. The fd is now closed first. |
| 11 | Info | `decide --target` is accepted but not used (decisions are per tool name). | **Made explicit:** output includes `"target_checked": false`. |
| 12 | Info | The spec's `stdout_is_tty` parameter was never implemented; IO-error paths were cut at 80 chars; a closed pipe exits 0 under `pipefail`. | The spec note is superseded (no TTY-dependent behaviour); paths are now shown up to 260 chars. A closed pipe keeps the **real** exit code (0 only for successful commands). |

Suspected and not reproduced: a symlink swapped in between the lstat check and the rename. That needs symlink privilege, which this
Windows account lacks. Its impact is low, because `os.replace` replaces the link itself and does not write through it.
Fine (reviewer): device names, ADS, UNC/`\?\` and junction targets are refused with no temp left; hardlinks are not written through;
nothing is mutated beyond the export file; no `@file` expansion; 20 000 random argv never raised; JSON is ASCII.

## Regression tests (`code/aiosh-mcp/tests/test_tool_registry_cli_security.py`, 18)
Result on pre-fix code: **18 of 18 fail.** On the fixed code: **18 passed**.
```
$ python -m pytest tests/ -k tool_registry -q
346 passed, 1 skipped, 1437 deselected, 1 warning in 31.29s
```
