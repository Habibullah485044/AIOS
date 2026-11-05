"""Regression tests for the tool registry CLI security review (T-03389).

Each test fails on the pre-T-03389 code (see docs/tasks/evidence/T-03389-security.md).
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from aiosh_mcp import tool_registry_cli as cli
from aiosh_mcp import tool_registry_data_model as reg

PKG_ROOT = Path(__file__).resolve().parents[1]


def run_cli(args, tmp_path, close_stdout_early=False, encoding=None):
    env = dict(os.environ, AIOSH_HOME=str(tmp_path))
    if encoding:
        env["PYTHONIOENCODING"] = encoding
    proc = subprocess.Popen([sys.executable, "-m", "aiosh_mcp.tool_registry_cli", *args], cwd=PKG_ROOT, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if close_stdout_early:
        proc.stdout.close()                                   # the reader goes away, like `| true` / `| head`
        err = proc.stderr.read()
        proc.wait(60)
        return proc.returncode, b"", err
    out, err = proc.communicate(timeout=60)
    return proc.returncode, out, err


# #1: a closed pipe on Windows is OSError(EINVAL), not BrokenPipeError.
@pytest.mark.parametrize("args", [["export"], ["list"], ["check", "aios.fs.read", "--json"]])
def test_closed_pipe_exits_quietly(args, tmp_path):
    code, _, err = run_cli(args, tmp_path, close_stdout_early=True)
    assert b"Traceback" not in err and code == (0 if args[0] != "check" else 0)


# #2: non-encodable text on a redirected (cp1252) stdout never crashes; a success stays a success.
def test_redirected_non_cp1252_output(tmp_path):
    code, out, err = run_cli(["check", "漢字"], tmp_path, encoding="cp1252")
    assert code == 1 and b"Traceback" not in err and b"\\u6f22" in out
    target = tmp_path / "漢.json"
    code, out, err = run_cli(["export", "--out", str(target)], tmp_path, encoding="cp1252")
    assert code == 0 and target.exists() and b"Traceback" not in err


# #3: usage errors never echo raw control bytes.
def test_usage_error_escapes_terminal_sequences(tmp_path):
    code, out, err = run_cli(["list", "\x1b]0;PWNED\x07\x1b[2J"], tmp_path)
    assert code == 2 and b"\x1b" not in err and b"\x07" not in err and b"\\x1b" in err and out == b""


# #4: no stdout at all (pythonw, closed fd 1).
def test_missing_stdout(monkeypatch):
    monkeypatch.setattr(cli.sys, "stdout", None)
    assert cli.main(["list"]) == 0


# #5: C1 controls, line/paragraph separators and bidi marks are not passed through.
@pytest.mark.parametrize("ch", ["\x9b", "\x85", " ", " ", "‎", "‏", "؜"])
def test_forbidden_text_covers_c1_separators_and_marks(ch):
    assert ch not in reg._shown(f"a{ch}b")
    assert ch not in cli._safe(f"a{ch}b") and cli._safe(f"a{ch}b").isascii()


# #6: an empty --out is an error, not a silent dump to stdout.
def test_empty_out_is_a_usage_error():
    r = cli.dispatch_cli(["export", "--out", ""])
    assert r.exit_code == 2 and r.error_code == "TOOLCLI_ERR_USAGE"


# #7: --json as argparse understands it (abbreviations), and a name that looks like --json is not the flag.
def test_json_flag_follows_argparse(capsys):
    cli.main(["list", "--js"])
    assert json.loads(capsys.readouterr().out)["subcommand"] == "list"
    cli.main(["check", "--", "--json"])
    assert not capsys.readouterr().out.lstrip().startswith("{")


# #8: errors go to stderr, so `export > file` never writes an error into the data file.
def test_errors_go_to_stderr(tmp_path, capsys):
    assert cli.main(["export", "--out", str(tmp_path)]) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and "TOOLCLI_ERR_IO" in captured.err


# #10: an interrupt right after the temp file is created still removes it.
def test_interrupt_after_mkstemp_leaves_no_temp(tmp_path, monkeypatch):
    def interrupted(*a, **k):
        raise KeyboardInterrupt
    monkeypatch.setattr(cli.os, "fdopen", interrupted)
    with pytest.raises(KeyboardInterrupt):
        cli._export_to(str(tmp_path / "c.json"), "{}")
    assert list(tmp_path.iterdir()) == []


# #11: decide says plainly that the target was not checked.
def test_decide_reports_target_not_checked():
    assert cli.dispatch_cli(["decide", "pentest.nmap", "--target", "10.0.0.5"]).data["target_checked"] is False
