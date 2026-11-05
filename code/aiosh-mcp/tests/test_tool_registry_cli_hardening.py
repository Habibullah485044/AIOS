"""Hardening tests for the tool registry CLI (T-03390): interrupts, help, export size cap."""

import pytest

from aiosh_mcp import tool_registry_cli as cli


def test_ctrl_c_exits_130_without_traceback(monkeypatch, capsys):
    def interrupted(_argv):
        raise KeyboardInterrupt
    monkeypatch.setattr(cli, "dispatch_cli", interrupted)
    assert cli.main(["list"]) == cli.EXIT_INTERRUPTED == 130
    captured = capsys.readouterr()
    assert "TOOLCLI_ERR_INTERRUPTED" in captured.err and "Traceback" not in captured.err and captured.out == ""


def test_interrupted_export_leaves_no_temp(tmp_path, monkeypatch):
    def interrupted(*a, **k):
        raise KeyboardInterrupt
    monkeypatch.setattr(cli.os, "replace", interrupted)
    monkeypatch.setattr(cli, "dispatch_cli", lambda argv: cli._export_to(str(tmp_path / "c.json"), "{}"))
    assert cli.main(["export"]) == 130
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("argv", [["--help"], ["-h"], ["list", "--help"], ["export", "-h", "--out", "x"]])
def test_help_is_success_and_lists_every_subcommand(argv, capsys):
    assert cli.main(argv) == 0
    out = capsys.readouterr().out
    assert all(sub in out for sub in cli.SUBCOMMANDS) and "exit codes" in out


def test_help_after_double_dash_is_a_name():
    r = cli.dispatch_cli(["check", "--", "--help"])
    assert r.exit_code == 1 and r.data["names"][0]["registered"] is False


def test_export_size_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "MAX_EXPORT_BYTES", 10)
    r = cli.dispatch_cli(["export", "--out", str(tmp_path / "c.json")])
    assert r.exit_code == 1 and r.error_code == "TOOLCLI_ERR_IO" and "refusing more than" in r.error
    assert list(tmp_path.iterdir()) == []
