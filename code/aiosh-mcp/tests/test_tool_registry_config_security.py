"""Regression tests for the tool registry configuration security review (T-03409).

Each test fails on the pre-T-03409 code (see docs/tasks/evidence/T-03409-security.md).
"""

import json
import os

import pytest

from aiosh_mcp import tool_registry_config as cfg
from aiosh_mcp import tool_registry_service as trs
from aiosh_mcp.agent_loop_config import hygiene_ok


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("AIOSH_HOME", str(tmp_path / "home"))
    for var in (cfg.ENV_CONFIG, cfg.ENV_MODE, *(f.env for f in cfg.FIELDS.values())):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)
    cfg.reset_process_config()
    yield monkeypatch
    cfg.reset_process_config()


# #1: NT object-manager prefixes reach SMB / devices; the shared path guard refuses them.
@pytest.mark.parametrize("path", ["\\??\\UNC\\127.0.0.1\\C$\\x\\cfg.json", "\\??\\C:\\x\\cfg.json", "??\\C:\\x.json"])
def test_nt_prefixes_are_refused(path):
    assert hygiene_ok(path) is False


# #10: device names with trailing space, dot or colon.
@pytest.mark.parametrize("path", ["CON .json", "nul:", "NUL .json", "aux.", "COM1 "])
def test_device_name_variants_are_refused(path):
    assert hygiene_ok(path) is False


# #2: a file that cannot be used must not throw away a strict request.
@pytest.mark.parametrize("content", [
    json.dumps({"mode": "strict", "typo_key": 1}).encode(),
    json.dumps({"mode": 1}).encode(),
    "{\"mode\": \"strict\"}".encode("utf-16"),
    b"{not json",
])
def test_rejected_file_counts_as_strict(env, tmp_path, content):
    p = tmp_path / "c.json"
    p.write_bytes(content)
    env.setenv(cfg.ENV_CONFIG, str(p))
    assert cfg.resolve()["config"]["mode"] == "strict"


def test_utf8_bom_is_accepted(env, tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"mode": "shadow", "report_max_lines": 9}), encoding="utf-8-sig")
    env.setenv(cfg.ENV_CONFIG, str(p))
    r = cfg.resolve()
    assert r["config"]["report_max_lines"] == 9 and r["errors"] == []


# #3: an env path that cannot be used counts as strict, it does not silently mean "no file".
@pytest.mark.parametrize("value", ["../../etc/x.json", "CON"])
def test_bad_env_path_counts_as_strict(env, value):
    env.setenv(cfg.ENV_CONFIG, value)
    assert cfg.resolve()["config"]["mode"] == "strict"


def test_missing_env_file_counts_as_strict(env, tmp_path):
    env.setenv(cfg.ENV_CONFIG, str(tmp_path / "missing.json"))
    assert cfg.resolve()["config"]["mode"] == "strict"


# #4: every consumer reads the one per-process resolution.
def test_consumers_agree(env, tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"mode": "strict", "unregistered_samples": 3}), encoding="utf-8")
    env.setenv(cfg.ENV_CONFIG, str(p))
    service = trs.ToolRegistryService()
    p.unlink()                                                   # file disappears after start-up
    assert trs.intended_mode() == "strict" == service.mode == cfg.process_config()["config"]["mode"]


# #5: the default file is not read from the working directory.
def test_default_file_is_not_cwd_relative(env, tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "tool_registry_config.json").write_text('{"report_max_lines": 7}', encoding="utf-8")
    (tmp_path / "tool_registry_config.json").write_text('{"report_max_lines": 7}', encoding="utf-8")
    assert cfg.resolve()["config"]["report_max_lines"] == 32
    assert os.path.dirname(cfg.default_config_path()) == os.path.abspath(str(tmp_path / "home"))


# #6: the disagreement log cannot be switched off.
def test_report_lines_cannot_be_zero(env):
    env.setenv("AIOSH_TOOL_REGISTRY_REPORT_MAX_LINES", "0")
    assert cfg.resolve()["config"]["report_max_lines"] == 1


# #7: duplicate keys are rejected (and so count as strict).
def test_duplicate_keys_are_rejected(env, tmp_path):
    p = tmp_path / "c.json"
    p.write_text('{"mode": "strict", "mode": "shadow"}', encoding="utf-8")
    env.setenv(cfg.ENV_CONFIG, str(p))
    r = cfg.resolve()
    assert r["config"]["mode"] == "strict" and any(e.startswith("TOOLREGCONF_ERR_PARSE") for e in r["errors"])


# #8: the internal-failure fallback fails closed.
def test_fallback_is_strict(env, monkeypatch):
    monkeypatch.setattr(cfg, "_resolve", lambda *a, **k: 1 / 0)
    assert cfg.resolve()["config"]["mode"] == "strict"


# #9: stats exposes error codes only.
def test_stats_exposes_codes_only(env, tmp_path):
    from aiosh_mcp import tool_registry_api as api
    from aiosh_mcp.server import mcp as server_app
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"secret_key_name": 1}), encoding="utf-8")
    env.setenv(cfg.ENV_CONFIG, str(p))
    stats = {t.name: t for t in server_app._tool_manager.list_tools()}[api.STATS_TOOL].fn()["data"]
    assert stats["config_errors"] == ["TOOLREGCONF_ERR_UNKNOWN_KEY"]
    assert "secret_key_name" not in json.dumps(stats)
