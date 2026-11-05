"""Unit tests for the tool registry CLI (T-03387; spec T-03384).

Boundaries, hostile input, the export failure modes (TOOLCLI-INV4) and safe output (TOOLCLI-INV3).
"""

import json
import os

import pytest

from aiosh_mcp import tool_registry_cli as cli
from aiosh_mcp import tool_registry_data_model as reg


def run(*argv):
    return cli.dispatch_cli(list(argv))


# --- boundaries ------------------------------------------------------------------------------------------------

def test_name_count_and_length_boundaries():
    assert run("check", *(["aios.fs.read"] * cli.MAX_NAMES)).exit_code == 0
    assert run("check", *(["aios.fs.read"] * (cli.MAX_NAMES + 1))).exit_code == 2
    assert run("get", "a" * cli.MAX_NAME_CHARS).exit_code == 1            # allowed length, just unregistered
    assert run("get", "a" * (cli.MAX_NAME_CHARS + 1)).exit_code == 2


def test_every_category_filter_works():
    total = 0
    for c in reg.Category:
        r = run("list", "--category", c.value)
        assert r.exit_code == 0 and all(e["category"] == c.value for e in r.data["entries"])
        total += r.data["count"]
    assert total == len(reg.default_catalog())


# --- hostile input ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("argv", [["get", None], ["check", 5], [b"list"], ["--json"], ["list", "--json", "extra"]])
def test_odd_argv_never_raises(argv):
    r = cli.dispatch_cli(argv)
    assert r.exit_code in (0, 1, 2)


def test_hostile_names_are_not_echoed_raw(capsys):
    hostile = "\x1b[2J‮pentest\nFAKE: ok"
    assert cli.main(["check", hostile]) == 1
    out = capsys.readouterr().out
    assert "\x1b" not in out and "‮" not in out and "FAKE: ok\n" not in out


def test_json_output_is_ascii_and_parseable(capsys):
    cli.main(["get", "pentest.ü‮", "--json"])
    raw = capsys.readouterr().out
    assert raw.isascii() and json.loads(raw)["data"]["registered"] is False


def test_usage_errors_go_to_stderr(capsys):
    assert cli.main(["list", "--category", "bad"]) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "TOOLCLI_ERR_USAGE" in captured.err


# --- export failure modes (TOOLCLI-INV4) --------------------------------------------------------------------------

def test_export_overwrites_a_regular_file_atomically(tmp_path):
    out = tmp_path / "c.json"
    out.write_text("old", encoding="utf-8")
    assert run("export", "--out", str(out)).exit_code == 0
    assert out.read_text(encoding="utf-8") == reg.default_catalog().export_json()


def test_export_to_missing_directory_fails_cleanly(tmp_path):
    r = run("export", "--out", str(tmp_path / "nope" / "c.json"))
    assert r.exit_code == 1 and r.error_code == "TOOLCLI_ERR_IO"
    assert not (tmp_path / "nope").exists()


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="no symlink support")
def test_export_refuses_a_symlink(tmp_path):
    real = tmp_path / "real.json"
    real.write_text("keep", encoding="utf-8")
    link = tmp_path / "link.json"
    try:
        os.symlink(real, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted here")
    r = run("export", "--out", str(link))
    assert r.exit_code == 1 and r.error_code == "TOOLCLI_ERR_IO" and real.read_text(encoding="utf-8") == "keep"


def test_failed_write_leaves_no_temp_file(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(cli.os, "replace", boom)
    r = run("export", "--out", str(tmp_path / "c.json"))
    assert r.exit_code == 1 and r.error_code == "TOOLCLI_ERR_IO" and "No space" in r.error
    assert list(tmp_path.iterdir()) == []


def test_catalog_unavailable(monkeypatch):
    def broken():
        raise reg.ToolRegistryError(reg.TOOLREG_ERR_DUPLICATE, "bad seed")
    monkeypatch.setattr(cli, "default_catalog", broken)
    r = run("list")
    assert r.exit_code == 1 and r.error_code == "TOOLCLI_ERR_UNAVAILABLE"


# --- closed pipe ---------------------------------------------------------------------------------------------------

def test_broken_pipe_exits_quietly(monkeypatch):
    class Closed:
        def write(self, *_):
            raise BrokenPipeError()

        def flush(self):
            raise BrokenPipeError()

        def fileno(self):
            raise ValueError("no fd")

    monkeypatch.setattr(cli.sys, "stdout", Closed())
    assert cli.main(["list"]) == 0
