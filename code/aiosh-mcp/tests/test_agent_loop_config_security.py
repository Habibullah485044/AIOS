"""Security tests for Agent Loop Hardening configuration (T-03309).

Abuse scenarios from docs/tasks/evidence/T-03309-security.md. The MCP server resolves
config at import, so every case here must neither raise nor hang.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from aiosh_mcp import agent_loop_config as alc

PKG_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    for f in alc.FIELDS.values():
        monkeypatch.delenv(f.env, raising=False)
    monkeypatch.delenv(alc.ENV_AGENT_LOOP_CONFIG, raising=False)
    monkeypatch.chdir(tmp_path)


def _file(tmp_path, text, name="cfg.json"):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


@pytest.mark.parametrize("digits", [400, 5000])
def test_s1_huge_json_integers_do_not_raise(tmp_path, digits):
    r = alc.resolve(arg_config=_file(tmp_path, '{"registry_capacity": 1' + "0" * digits + "}"))
    assert r["config"] == alc.default_config()
    assert r["source"]["_file"] == "config_invalid"


def test_s1_huge_override_does_not_raise():
    r = alc.resolve(overrides={"registry_capacity": 10 ** 400})
    assert r["config"]["registry_capacity"] == 256
    assert r["rejected"]["registry_capacity"] == "argument_invalid"


def _resolve_in_subprocess(env_path: str, timeout: float = 20.0) -> dict:
    code = "import json; from aiosh_mcp import agent_loop_config as a; print(json.dumps(a.resolve()))"
    proc = subprocess.run([sys.executable, "-c", code], cwd=PKG_ROOT, timeout=timeout,
                          env=dict(os.environ, AIOSH_AGENT_LOOP_CONFIG=env_path),
                          stdin=subprocess.PIPE, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


@pytest.mark.parametrize("path", ["CON", "nul", "COM1.json", "conin$", r"\\.\pipe\aios", r"\\attacker\share\c.json",
                                  "//attacker/share/c.json"])
def test_s2_device_and_unc_paths_rejected_without_hanging(path):
    out = _resolve_in_subprocess(path)  # TimeoutExpired here would mean a hang
    assert out["source"]["_file"] in ("env_invalid", "config_invalid")
    assert out["config"] == alc.default_config()


@pytest.mark.parametrize("path", ["CON", r"\\host\share\x.json", "dir"])
def test_s2_explicit_paths_also_guarded(tmp_path, path):
    (tmp_path / "dir").mkdir()
    r = alc.resolve(arg_config=path)
    assert r["source"]["_file"] == "config_invalid"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO")
def test_s2_fifo_rejected(tmp_path):
    fifo = tmp_path / "cfg.fifo"
    os.mkfifo(fifo)
    out = _resolve_in_subprocess(str(fifo))
    assert out["source"]["_file"] == "config_invalid"


def test_s2_server_import_survives_hostile_config(tmp_path):
    bad = _file(tmp_path, '{"registry_capacity": 1' + "0" * 400 + "}")
    proc = subprocess.run([sys.executable, "-c", "import aiosh_mcp.server; print('ok')"], cwd=PKG_ROOT,
                          env=dict(os.environ, AIOSH_AGENT_LOOP_CONFIG=bad, AIOSH_HOME=str(tmp_path)),
                          capture_output=True, text=True, timeout=120)
    assert proc.stdout.strip().endswith("ok"), proc.stderr[-500:]


def test_s3_busy_wait_stays_under_half_the_call_bound():
    r = alc.resolve(overrides={"mcp_call_timeout_s": 1, "db_busy_timeout_ms": 30000})
    assert r["config"]["db_busy_timeout_ms"] * 2 <= r["config"]["mcp_call_timeout_s"] * 1000
    assert any("db_busy_timeout_ms" in e for e in r["errors"])


def test_s4_errors_are_masked_truncated_and_path_free(tmp_path):
    secret = "sk-ant-api03-" + "S" * 40
    sub = tmp_path / "private-user-dir"
    sub.mkdir()
    r = alc.resolve(arg_config=_file(sub, json.dumps({"registry_capacity": secret, "k" * 5000: 1})))
    blob = json.dumps(r)
    assert secret[:20] not in blob
    assert "private-user-dir" not in blob
    assert all(len(e) <= alc.MAX_ERROR_CHARS for e in r["errors"])
    r = alc.resolve(overrides={"registry_capacity": "nan" + " " * 60000})
    assert all(len(e) <= alc.MAX_ERROR_CHARS for e in r["errors"])


def test_s5_source_labels_are_truthful(tmp_path, monkeypatch):
    monkeypatch.setenv("AIOSH_AGENT_LOOP_MAX_ITERATIONS", "lots")
    r = alc.resolve(arg_config=_file(tmp_path, '{"default_max_iterations": 7}'))
    assert (r["config"]["default_max_iterations"], r["source"]["default_max_iterations"]) == (7, "file")
    assert r["rejected"] == {"default_max_iterations": "env_invalid"}


def test_s6_locked_controls_still_unrepresentable(tmp_path):
    for key in alc.LOCKED_KEYS:
        r = alc.resolve(arg_config=_file(tmp_path, json.dumps({key: 0})), overrides={key: 0})
        assert key not in r["config"]
        assert r["source"]["_file"] == "config_invalid"
