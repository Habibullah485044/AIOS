"""Unit tests for Agent Loop Hardening configuration (T-03307).

Valid input, invalid input, boundary values and the primary failure mode
(a defective config must fail closed to defaults and be reported).
"""

import json

import pytest

from aiosh_mcp import agent_loop_config as alc


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    for f in alc.FIELDS.values():
        monkeypatch.delenv(f.env, raising=False)
    monkeypatch.delenv(alc.ENV_AGENT_LOOP_CONFIG, raising=False)
    monkeypatch.chdir(tmp_path)


def _file(tmp_path, body, name="cfg.json"):
    p = tmp_path / name
    p.write_text(body if isinstance(body, str) else json.dumps(body), encoding="utf-8")
    return str(p)


# ---- boundaries: every field accepts both edges and clamps one step past them ----

@pytest.mark.parametrize("key", sorted(alc.FIELDS))
def test_each_field_edges_and_clamp(tmp_path, key):
    f = alc.FIELDS[key]
    for edge in (f.lo, f.hi):
        r = alc.resolve(overrides={key: edge})
        assert r["config"][key] == f.kind(edge)
        assert r["errors"] == []
    step = 1 if f.kind is int else 0.5
    low = alc.resolve(overrides={key: f.lo - step})
    high = alc.resolve(overrides={key: f.hi + step})
    assert (low["config"][key], high["config"][key]) == (f.kind(f.lo), f.kind(f.hi))
    assert all(alc.AGENTLOOPCONF_ERR_BOUNDS in r["errors"][0] for r in (low, high))


def test_numeric_strings_accepted_from_env(monkeypatch):
    monkeypatch.setenv("AIOSH_AGENT_LOOP_MCP_CALL_TIMEOUT_S", " 2.5 ")
    monkeypatch.setenv("AIOSH_AGENT_LOOP_REGISTRY_CAPACITY", "12")
    c = alc.resolve()["config"]
    assert (c["mcp_call_timeout_s"], c["registry_capacity"]) == (2.5, 12)


# ---- invalid input: fail closed to defaults, reported (AGENTLOOPCONF-INV1/INV4) ----

_DEFECTS = [
    (" " * (alc.MAX_CONFIG_FILE_BYTES + 1), alc.AGENTLOOPCONF_ERR_FILE_SIZE),
    ("{nope", alc.AGENTLOOPCONF_ERR_PARSE),
    ("[1, 2]", alc.AGENTLOOPCONF_ERR_PARSE),
    ("[" * 60000, alc.AGENTLOOPCONF_ERR_PARSE),
    (b"\xff\xfe\x00".decode("latin-1"), alc.AGENTLOOPCONF_ERR_PARSE),
    (json.dumps({"registry_capacity": "lots"}), alc.AGENTLOOPCONF_ERR_PARSE),
    (json.dumps({"registry_capacity": True}), alc.AGENTLOOPCONF_ERR_PARSE),
    (json.dumps({"registry_capacity": None}), alc.AGENTLOOPCONF_ERR_PARSE),
    (json.dumps({"not_a_field": 1}), alc.AGENTLOOPCONF_ERR_UNKNOWN_KEY),
    (json.dumps({"require_grant": False}), alc.AGENTLOOPCONF_ERR_LOCKED),
    (json.dumps({"max_args_bytes": 10_000_000, "registry_capacity": 8}), alc.AGENTLOOPCONF_ERR_LOCKED),
]
_DEFECT_IDS = ["oversize", "bad-json", "array", "deep-nesting", "bad-utf8", "non-numeric", "bool", "null",
               "unknown-key", "locked-key", "locked-plus-valid"]


@pytest.mark.parametrize("body,code", _DEFECTS, ids=_DEFECT_IDS)
def test_defective_file_is_ignored_entirely(tmp_path, body, code):
    r = alc.resolve(arg_config=_file(tmp_path, body))
    assert r["source"]["_file"] == "config_invalid"
    assert r["config"] == alc.default_config()
    assert r["errors"][0].startswith(code)


def test_missing_file_is_io_error(tmp_path):
    r = alc.resolve(arg_config=str(tmp_path / "absent.json"))
    assert r["errors"][0].startswith(alc.AGENTLOOPCONF_ERR_IO)
    assert r["config"] == alc.default_config()


def test_bad_env_value_keeps_lower_level(tmp_path, monkeypatch):
    monkeypatch.setenv("AIOSH_AGENT_LOOP_MAX_ITERATIONS", "many")
    r = alc.resolve(arg_config=_file(tmp_path, {"default_max_iterations": 9}))
    assert r["source"]["default_max_iterations"] == "env_invalid"
    assert r["config"]["default_max_iterations"] == 9
    assert any(e.startswith(alc.AGENTLOOPCONF_ERR_ENV) for e in r["errors"])


def test_bad_overrides_reported_not_applied():
    r = alc.resolve(overrides={"require_grant": False, "bogus": 3, "registry_capacity": "x"})
    assert r["config"] == alc.default_config()
    assert [e.split(":")[0] for e in r["errors"]] == [
        alc.AGENTLOOPCONF_ERR_LOCKED, alc.AGENTLOOPCONF_ERR_UNKNOWN_KEY, "registry_capacity"]


@pytest.mark.parametrize("value,ok", [
    ("cfg.json", True), ("C:\\aios\\cfg.json", True), ("", False), ("   ", False),
    ("../cfg.json", False), ("a\x00b", False), ("a\nb", False), ("a\x7fb", False),
    ("x" * 1024, True), ("x" * 1025, False), (None, False), (42, False),
])
def test_hygiene_predicate_is_total(value, ok):
    assert alc.hygiene_ok(value) is ok


def test_default_file_used_when_present(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "agent_loop_config.json").write_text(json.dumps({"snapshot_steps_tail": 3}))
    r = alc.resolve()
    assert (r["config"]["snapshot_steps_tail"], r["source"]["_file"]) == (3, "file")


def test_every_resolved_value_has_a_source(tmp_path, monkeypatch):
    monkeypatch.setenv("AIOSH_AGENT_LOOP_DB_BUSY_TIMEOUT_MS", "200")
    r = alc.resolve(arg_config=_file(tmp_path, {"registry_capacity": 5}), overrides={"snapshot_steps_tail": 0})
    assert set(r["source"]) == set(alc.FIELDS) | {"_file"}
    assert set(r["source"].values()) <= set(alc.CONFIG_SOURCES)


def test_loop_config_for_rejects_unknown_field():
    with pytest.raises(TypeError):
        alc.loop_config_for("loop-config-unit-01", alc.resolve(), max_turns=5)
