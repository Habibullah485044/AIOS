"""Unit tests for the tool registry configuration (T-03407; spec T-03404).

Exact bounds, hostile file contents, the never-raises guarantee, and per-process caching.
"""

import json
import threading

import pytest

from aiosh_mcp import tool_registry_config as cfg


@pytest.fixture
def env(monkeypatch, tmp_path):
    for var in (cfg.ENV_CONFIG, cfg.ENV_MODE, *(f.env for f in cfg.FIELDS.values())):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)
    cfg.reset_process_config()
    yield monkeypatch
    cfg.reset_process_config()


def use_file(env, tmp_path, content):
    p = tmp_path / "c.json"
    p.write_bytes(content if isinstance(content, bytes) else json.dumps(content).encode())
    env.setenv(cfg.ENV_CONFIG, str(p))


@pytest.mark.parametrize("key", list(cfg.FIELDS))
def test_exact_bounds(env, tmp_path, key):
    f = cfg.FIELDS[key]
    for value, expect, clamped in ((f.lo, f.lo, False), (f.hi, f.hi, False), (f.lo - 1, f.lo, True),
                                   (f.hi + 1, f.hi, True)):
        use_file(env, tmp_path, {key: value})
        r = cfg.resolve()
        assert r["config"][key] == expect
        assert any(e.startswith("TOOLREGCONF_ERR_BOUNDS") for e in r["errors"]) is clamped


def test_file_exactly_at_the_size_cap_is_read(env, tmp_path):
    body = json.dumps({"report_max_lines": 9})
    use_file(env, tmp_path, (body + " " * (cfg.MAX_CONFIG_FILE_BYTES - len(body))).encode())
    assert cfg.resolve()["config"]["report_max_lines"] == 9


@pytest.mark.parametrize("content", [b"\xff\xfe\x00bad", b"", b"null", b"1e309", b'{"report_max_lines": 1e400}',
                                     b'{"report_max_lines": ' + b"9" * 5000 + b"}", b"[" * 100000 + b"]" * 100000,
                                     b'{"mode": "strict", "mode": "shadow"}'],
                         ids=["bad-utf8", "empty", "null", "huge-float", "inf-number", "5000-digit-int", "deep-nesting",
                              "duplicate-keys"])
def test_hostile_files_never_raise(env, tmp_path, content):
    use_file(env, tmp_path, content)
    r = cfg.resolve()
    assert set(r["config"]) == {"mode", *cfg.FIELDS}


def test_duplicate_mode_keys_cannot_launder_strict(env, tmp_path):
    # json keeps the last duplicate; the env still makes it strict (strictest wins across sources)
    use_file(env, tmp_path, b'{"mode": "strict", "mode": "shadow"}')
    env.setenv(cfg.ENV_MODE, "strict")
    assert cfg.resolve()["config"]["mode"] == "strict"


@pytest.mark.parametrize("value", ["", "   ", "　"])
def test_blank_mode_values_are_no_opinion(env, value):
    env.setenv(cfg.ENV_MODE, value)
    assert cfg.resolve()["config"]["mode"] == "shadow"


@pytest.mark.parametrize("value", ["ＳＴＲＩＣＴ", "strict\n", "Strict", "off", "0", "none"])
def test_variants_and_unknowns_are_strict(env, value):
    env.setenv(cfg.ENV_MODE, value)
    assert cfg.resolve()["config"]["mode"] == "strict"


def test_resolve_never_raises_even_if_internals_fail(env, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("bug")
    monkeypatch.setattr(cfg, "_resolve", boom)
    r = cfg.resolve()
    assert r["config"]["mode"] == "shadow" and r["errors"][0].startswith("TOOLREGCONF_ERR_IO")
    env.setenv(cfg.ENV_MODE, "strict")
    assert cfg.resolve()["config"]["mode"] == "strict"            # even the fallback fails closed


def test_process_config_is_resolved_once(env, monkeypatch):
    calls = []
    real = cfg.resolve
    monkeypatch.setattr(cfg, "resolve", lambda *a, **k: calls.append(1) or real(*a, **k))
    threads = [threading.Thread(target=cfg.process_config) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(calls) == 1 and cfg.process_config() is cfg.process_config()


def test_errors_are_bounded(env, tmp_path):
    use_file(env, tmp_path, {"x" * 5000: 1})
    r = cfg.resolve()
    assert all(len(e) <= cfg.MAX_ERROR_CHARS for e in r["errors"])
