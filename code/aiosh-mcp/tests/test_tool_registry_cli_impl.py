"""Implementation tests for the tool registry CLI (T-03386; spec T-03384)."""

import hashlib
import json

import pytest

from aiosh_mcp import tool_registry_cli as cli
from aiosh_mcp.tool_registry_data_model import default_catalog

C = default_catalog()


def run(*argv):
    return cli.dispatch_cli(list(argv))


def test_list_and_filter():
    r = run("list", "--json")
    assert r.exit_code == 0 and r.data["count"] == len(C)
    p = run("list", "--category", "pentest")
    assert p.exit_code == 0 and {e["category"] for e in p.data["entries"]} == {"pentest"}


def test_get_registered_and_unregistered():
    r = run("get", "aios_pentest_nmap")
    assert r.exit_code == 0 and r.data["registered"] is True and r.data["entry"]["canonical"] == "pentest.nmap"
    u = run("get", "pentest.newthing")
    assert u.exit_code == 1 and u.data["registered"] is False and u.data["entry"]["irreversible"] is True


def test_decide_modes():
    r = run("decide", "pentest.tshark", "--target", "/tmp/c.pcap")
    assert r.exit_code == 0 and r.data["scope_kinds"] == ["network", "path"] and r.data["disagreements"] == ["scope"]
    s = run("decide", "aios.unknown.x", "--mode", "strict")
    assert s.data["mode"] == "strict" and s.data["requires_grant"] is True


def test_check_exit_codes():
    ok = run("check", "aios.fs.read", "pentest.nmap")
    assert ok.exit_code == 0 and ok.data["unregistered"] == 0
    bad = run("check", "aios.fs.read", "nope.tool")
    assert bad.exit_code == 1 and bad.data["unregistered"] == 1
    assert [n["registered"] for n in bad.data["names"]] == [True, False]


def test_export_stdout_and_file(tmp_path):
    r = run("export")
    assert r.exit_code == 0 and r.data["export"] == C.export_json()
    out = tmp_path / "catalog.json"
    f = run("export", "--out", str(out))
    text = out.read_text(encoding="utf-8")
    assert f.exit_code == 0 and text == C.export_json()
    assert f.data["bytes"] == len(text.encode()) and f.data["sha256"] == hashlib.sha256(text.encode()).hexdigest()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["catalog.json"]          # no temp files left


def test_export_refuses_directories(tmp_path):
    r = run("export", "--out", str(tmp_path))
    assert r.exit_code == 1 and r.error_code == "TOOLCLI_ERR_IO"


@pytest.mark.parametrize("argv", [[], ["nope"], ["list", "--category", "bad"], ["get"], ["get", "a\x00b"],
                                  ["check"], ["check", "x" * 257], ["check"] + ["n"] * 257,
                                  ["decide", "x", "--mode", "loose"]])
def test_usage_errors(argv):
    r = run(*argv)
    assert r.exit_code == 2 and r.error_code == "TOOLCLI_ERR_USAGE"


def test_main_prints_json_and_human(capsys):
    assert cli.main(["get", "aios_fs_read", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["data"]["entry"]["canonical"] == "aios.fs.read"
    assert cli.main(["get", "aios_fs_read"]) == 0
    assert "aios.fs.read" in capsys.readouterr().out
    assert cli.main(["export"]) == 0
    assert capsys.readouterr().out.strip() == C.export_json()                       # export prints exactly the JSON


def test_console_script_declared():
    from pathlib import Path
    text = (Path(cli.__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    assert 'aiosh-tool-registry = "aiosh_mcp.tool_registry_cli:main"' in text
