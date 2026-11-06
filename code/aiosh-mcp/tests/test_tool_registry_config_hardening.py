"""Hardening tests for the tool registry configuration (T-03410): problems are visible, failures are isolated."""

import io
import json
import sys

import pytest

from aiosh_mcp import audit_client
from aiosh_mcp import tool_registry_config as cfg


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("AIOSH_HOME", str(tmp_path / "home"))
    for var in (cfg.ENV_CONFIG, cfg.ENV_MODE, *(f.env for f in cfg.FIELDS.values())):
        monkeypatch.delenv(var, raising=False)
    cfg.reset_process_config()
    yield monkeypatch
    cfg.reset_process_config()


def test_problems_are_announced_once_on_stderr(env, tmp_path, capsys):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"nope": 1}), encoding="utf-8")
    env.setenv(cfg.ENV_CONFIG, str(p))
    cfg.process_config()
    cfg.process_config()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.count("tool registry config: 1 problem(s); mode=strict") == 1
    assert "TOOLREGCONF_ERR_UNKNOWN_KEY" in captured.err


def test_clean_config_is_silent(env, capsys):
    cfg.process_config()
    assert capsys.readouterr().err == ""


def test_announcement_never_breaks_on_a_closed_stderr(env, tmp_path, monkeypatch):
    p = tmp_path / "c.json"
    p.write_text("{bad", encoding="utf-8")
    env.setenv(cfg.ENV_CONFIG, str(p))
    closed = io.StringIO()
    closed.close()
    monkeypatch.setattr(sys, "stderr", closed)
    assert cfg.process_config()["config"]["mode"] == "strict"


def test_default_path_failure_keeps_env_values(env, monkeypatch):
    def boom():
        raise OSError("no home")
    monkeypatch.setattr(audit_client, "default_db_path", boom)
    env.setenv("AIOSH_TOOL_REGISTRY_REPORT_MAX_LINES", "9")
    r = cfg.resolve()
    assert r["config"]["report_max_lines"] == 9 and r["config"]["mode"] == "strict"
    assert r["errors"][0].startswith("TOOLREGCONF_ERR_IO")
