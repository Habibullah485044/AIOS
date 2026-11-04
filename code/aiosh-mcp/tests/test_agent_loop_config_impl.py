"""Implementation tests for Agent Loop Hardening configuration (T-03306)."""

import json

import pytest

from aiosh_mcp import agent_loop_config as alc


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    for f in alc.FIELDS.values():
        monkeypatch.delenv(f.env, raising=False)
    monkeypatch.delenv(alc.ENV_AGENT_LOOP_CONFIG, raising=False)
    monkeypatch.chdir(tmp_path)  # no docs/agent_loop_config.json here


def _file(tmp_path, doc, name="cfg.json"):
    p = tmp_path / name
    p.write_text(doc if isinstance(doc, str) else json.dumps(doc), encoding="utf-8")
    return str(p)


def test_defaults_when_nothing_configured():
    r = alc.resolve()
    assert r["config"] == alc.default_config()
    assert set(r["source"].values()) == {"default"}
    assert r["errors"] == []


def test_precedence_argument_over_env_over_file_over_default(tmp_path, monkeypatch):
    path = _file(tmp_path, {"default_max_iterations": 10, "registry_capacity": 64, "snapshot_steps_tail": 7})
    monkeypatch.setenv("AIOSH_AGENT_LOOP_MAX_ITERATIONS", "20")
    monkeypatch.setenv("AIOSH_AGENT_LOOP_REGISTRY_CAPACITY", "32")
    r = alc.resolve(arg_config=path, overrides={"default_max_iterations": 30})
    c, s = r["config"], r["source"]
    assert (c["default_max_iterations"], s["default_max_iterations"]) == (30, "argument")
    assert (c["registry_capacity"], s["registry_capacity"]) == (32, "env")
    assert (c["snapshot_steps_tail"], s["snapshot_steps_tail"]) == (7, "file")
    assert (c["mcp_call_timeout_s"], s["mcp_call_timeout_s"]) == (15.0, "default")
    assert s["_file"] == "file"


def test_env_config_path_and_hygiene(tmp_path, monkeypatch):
    monkeypatch.setenv(alc.ENV_AGENT_LOOP_CONFIG, _file(tmp_path, {"default_max_total_tokens": 1000}))
    assert alc.resolve()["config"]["default_max_total_tokens"] == 1000
    monkeypatch.setenv(alc.ENV_AGENT_LOOP_CONFIG, "../../etc/agent_loop.json")
    r = alc.resolve()
    assert r["source"]["_file"] == "env_invalid"
    assert r["config"]["default_max_total_tokens"] == 32768


def test_clamping_is_reported(tmp_path):
    r = alc.resolve(arg_config=_file(tmp_path, {"registry_capacity": 10_000, "mcp_call_timeout_s": 0}))
    assert r["config"]["registry_capacity"] == 256
    assert r["config"]["mcp_call_timeout_s"] == 1.0
    assert sum(alc.AGENTLOOPCONF_ERR_BOUNDS in e for e in r["errors"]) == 2


def test_loop_config_for_uses_resolved_defaults_and_explicit_wins(tmp_path):
    r = alc.resolve(arg_config=_file(tmp_path, {"default_max_iterations": 7, "default_total_timeout_ms": 60000}))
    lc = alc.loop_config_for("loop-config-impl-01", r, max_iterations=9, max_total_tokens=None)
    assert (lc.max_iterations, lc.total_timeout_ms, lc.max_total_tokens) == (9, 60000.0, 32768)
    lc.validate_bounds()


def test_validate_rejects_unknown_and_locked():
    assert alc.validate({"default_max_iterations": 500})["default_max_iterations"] == 100
    with pytest.raises(ValueError, match=alc.AGENTLOOPCONF_ERR_UNKNOWN_KEY):
        alc.validate({"bogus": 1})
    with pytest.raises(ValueError, match=alc.AGENTLOOPCONF_ERR_LOCKED):
        alc.validate({"require_grant": False})
