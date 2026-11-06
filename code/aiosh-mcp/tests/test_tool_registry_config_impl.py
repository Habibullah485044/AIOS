"""Implementation tests for the tool registry configuration (T-03406; spec T-03404)."""

import json

import pytest

from aiosh_mcp import tool_registry_config as cfg
from aiosh_mcp import tool_registry_service as trs


@pytest.fixture
def env(monkeypatch, tmp_path):
    for var in (cfg.ENV_CONFIG, cfg.ENV_MODE, *(f.env for f in cfg.FIELDS.values())):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)                              # no default docs/tool_registry_config.json here
    cfg.reset_process_config()
    yield monkeypatch
    cfg.reset_process_config()


def write(tmp_path, doc, name="c.json"):
    p = tmp_path / name
    p.write_text(doc if isinstance(doc, str) else json.dumps(doc), encoding="utf-8")
    return str(p)


def test_defaults(env):
    r = cfg.resolve()
    assert r["config"] == {"mode": "shadow", "report_max_lines": 32, "unregistered_samples": 50}
    assert r["errors"] == [] and r["path"] is None and r["sources"]["mode"] == "default"


def test_precedence_argument_env_file_default(env, tmp_path):
    env.setenv(cfg.ENV_CONFIG, write(tmp_path, {"report_max_lines": 10, "unregistered_samples": 20}))
    env.setenv("AIOSH_TOOL_REGISTRY_REPORT_MAX_LINES", "11")
    r = cfg.resolve(overrides={"report_max_lines": 12})
    assert (r["config"]["report_max_lines"], r["sources"]["report_max_lines"]) == (12, "argument")
    assert (r["config"]["unregistered_samples"], r["sources"]["unregistered_samples"]) == (20, "file")
    assert cfg.resolve()["config"]["report_max_lines"] == 11


@pytest.mark.parametrize("arg,env_mode,file_mode,expected", [
    (None, None, None, "shadow"), (None, "strict", "shadow", "strict"), (None, "shadow", "strict", "strict"),
    ("shadow", "strict", None, "strict"), ("strict", None, "shadow", "strict"), (None, "strct", None, "strict"),
    (None, None, "loose", "strict"), (None, "", None, "shadow"), (None, " SHADOW ", None, "shadow"),
])
def test_mode_is_strictest_wins(env, tmp_path, arg, env_mode, file_mode, expected):
    if env_mode is not None:
        env.setenv(cfg.ENV_MODE, env_mode)
    if file_mode is not None:
        env.setenv(cfg.ENV_CONFIG, write(tmp_path, {"mode": file_mode}))
    assert cfg.resolve(arg_mode=arg)["config"]["mode"] == expected


@pytest.mark.parametrize("doc,code", [
    ({"catalog": []}, "TOOLREGCONF_ERR_LOCKED"), ({"grant_params": []}, "TOOLREGCONF_ERR_LOCKED"),
    ({"nope": 1}, "TOOLREGCONF_ERR_UNKNOWN_KEY"), ({"report_max_lines": "5"}, "TOOLREGCONF_ERR_PARSE"),
    ({"report_max_lines": True}, "TOOLREGCONF_ERR_PARSE"), ({"mode": 1}, "TOOLREGCONF_ERR_PARSE"),
    ("[1, 2]", "TOOLREGCONF_ERR_PARSE"), ("{not json", "TOOLREGCONF_ERR_PARSE"),
])
def test_bad_files_are_ignored_whole(env, tmp_path, doc, code):
    if isinstance(doc, dict):
        doc = {**doc, "report_max_lines": 7} if "report_max_lines" not in doc else doc
    env.setenv(cfg.ENV_CONFIG, write(tmp_path, doc))
    r = cfg.resolve()
    assert r["config"]["report_max_lines"] == 32                    # nothing from the bad file applied
    assert any(e.startswith(code) for e in r["errors"])


def test_bounds_are_clamped_and_reported(env, tmp_path):
    env.setenv(cfg.ENV_CONFIG, write(tmp_path, {"report_max_lines": 5000, "unregistered_samples": -3}))
    r = cfg.resolve()
    assert (r["config"]["report_max_lines"], r["config"]["unregistered_samples"]) == (1000, 0)
    assert sum(e.startswith("TOOLREGCONF_ERR_BOUNDS") for e in r["errors"]) == 2


def test_bad_env_number_keeps_lower_levels(env):
    env.setenv("AIOSH_TOOL_REGISTRY_UNREGISTERED_SAMPLES", "lots")
    r = cfg.resolve()
    assert r["config"]["unregistered_samples"] == 50 and r["errors"][0].startswith("TOOLREGCONF_ERR_ENV")


def test_oversize_and_hygiene(env, tmp_path):
    env.setenv(cfg.ENV_CONFIG, write(tmp_path, " " * (cfg.MAX_CONFIG_FILE_BYTES + 1)))
    assert cfg.resolve()["errors"][0].startswith("TOOLREGCONF_ERR_FILE_SIZE")
    env.setenv(cfg.ENV_CONFIG, "../../etc/passwd")
    assert cfg.resolve()["errors"][0].startswith("TOOLREGCONF_ERR_IO")
    env.setenv(cfg.ENV_CONFIG, "CON")
    assert cfg.resolve()["errors"][0].startswith("TOOLREGCONF_ERR_IO")
    env.setenv(cfg.ENV_CONFIG, str(tmp_path))                        # a directory
    assert cfg.resolve()["errors"][0].startswith("TOOLREGCONF_ERR_IO")


def test_default_file_is_used_when_present(env, tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "tool_registry_config.json").write_text('{"mode": "strict"}', encoding="utf-8")
    r = cfg.resolve()
    assert r["config"]["mode"] == "strict" and r["sources"]["mode"] == "file"


def test_service_uses_the_config(env, tmp_path):
    env.setenv(cfg.ENV_CONFIG, write(tmp_path, {"mode": "strict", "unregistered_samples": 2}))
    s = trs.ToolRegistryService()
    for i in range(5):
        s.decide(f"aios.u.n{i}")
    assert s.mode == "strict" and len(s.stats()["unregistered_samples"]) == 2


def test_resolving_writes_nothing(env, tmp_path):
    before = sorted(p.name for p in tmp_path.iterdir())
    cfg.resolve()
    assert sorted(p.name for p in tmp_path.iterdir()) == before
