"""Regression tests for the tool registry service security review (T-03379).

Each test fails on the pre-T-03379 code (see docs/tasks/evidence/T-03379-security.md).
"""

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from aiosh_mcp import _dispatch
from aiosh_mcp import tool_registry_service as trs
from aiosh_mcp.agent_loop_policy import evaluate_step

PKG_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def fresh(monkeypatch, tmp_path):
    monkeypatch.setenv("AIOSH_HOME", str(tmp_path))
    monkeypatch.setattr(trs, "_SERVICE", None)
    monkeypatch.setattr(trs, "_SERVICE_ERROR", None, raising=False)
    monkeypatch.setattr(trs, "_REPORTED", set(), raising=False)
    monkeypatch.setattr(trs, "_REPORT_STATE", {"lines": 0, "suppressed": 0}, raising=False)
    monkeypatch.setattr(trs, "_WARNED", set(), raising=False)
    monkeypatch.setattr(_dispatch, "_REGISTRY_FAILURE_LOGGED", False)


# #1: an undrained stderr pipe must not stall tool calls.
BLOCKED_PIPE_PROBE = r"""
import time
from aiosh_mcp import _dispatch
start = time.monotonic(); n = 0
while time.monotonic() - start < 3:
    _dispatch._registry_require_grant("aios.mystery.task", None, False)
    n += 1
print(n, flush=True)
"""


def test_undrained_stderr_does_not_block_calls(tmp_path):
    proc = subprocess.Popen([sys.executable, "-c", BLOCKED_PIPE_PROBE], cwd=PKG_ROOT, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=dict(os.environ, AIOSH_HOME=str(tmp_path)))
    import threading
    got = []
    reader = threading.Thread(target=lambda: got.append(proc.stdout.readline()), daemon=True)
    reader.start()                                       # stderr is deliberately never read
    reader.join(30)
    proc.kill()
    proc.wait(10)
    assert got and got[0].strip(), "child blocked on a full stderr pipe"          # old code: hung here
    assert int(got[0]) > 1000                            # was ~21 calls before the pipe filled and blocked


def test_identical_disagreements_are_logged_once_and_capped(capsys):
    s = trs.ToolRegistryService(mode="shadow")
    for _ in range(1000):
        trs.report(s.decide("aios.mystery.task"), "aios.mystery.task", "dispatch")
    assert capsys.readouterr().err.count("\n") == 1
    for i in range(200):
        trs.report(s.decide(f"aios.u{i}"), f"aios.u{i}", "dispatch")
    assert capsys.readouterr().err.count("\n") == trs.MAX_REPORT_LINES - 1
    assert trs.report_stats()["suppressed"] > 0


# #2: a mistyped strict mode fails closed instead of silently dropping to legacy-only rules.
@pytest.mark.parametrize("value", ["strct", "enforce", "1", "ｓｔｒｉｃｔ", "STRICT "])
def test_unrecognised_or_variant_mode_is_strict(value, monkeypatch, capsys):
    monkeypatch.setenv(trs.ENV_MODE, value)
    assert _dispatch._registry_require_grant("aios.mystery.task", None, False) is True
    assert evaluate_step("aios.mystery.read", ["/tmp/x"], {"path": "/tmp/x"}).irreversible is True


def test_broken_registry_fails_closed_when_strict_was_asked(monkeypatch, capsys):
    monkeypatch.setenv(trs.ENV_MODE, "strict")

    def boom():
        raise RuntimeError("catalog exploded")
    monkeypatch.setattr(trs, "service", boom)
    assert _dispatch._registry_require_grant("aios.mystery.task", None, False) is True
    assert evaluate_step("aios.mystery.read", ["/tmp/x"], {"path": "/tmp/x"}).irreversible is True
    assert "strict" in capsys.readouterr().err


def test_empty_mode_is_shadow(monkeypatch):
    monkeypatch.setenv(trs.ENV_MODE, "")
    assert _dispatch._registry_require_grant("aios.mystery.task", None, False) is False


# #4: a failed build is remembered, not retried on every call.
def test_failed_service_build_is_cached(monkeypatch):
    calls = []

    class Boom:
        def __init__(self, *a, **k):
            calls.append(1)
            raise RuntimeError("bad")
    monkeypatch.setattr(trs, "ToolRegistryService", Boom)
    for _ in range(5):
        with pytest.raises(RuntimeError):
            trs.service()
    assert len(calls) == 1


# #5: the canonical field is masked too.
def test_canonical_is_masked_in_reports(capsys):
    token = "xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx"
    s = trs.ToolRegistryService(mode="shadow")
    trs.report(s.decide(token), token, "agent_loop")
    err = capsys.readouterr().err
    assert "abcdefghijklmnop" not in err and json.loads(err)["canonical"].startswith("[REDACTED")


# #6: samples are keyed per process (not a plain sha256 of the name); disagreements are sorted.
def test_samples_are_not_plain_hashes_and_disagreements_sorted():
    import hashlib
    s = trs.ToolRegistryService(mode="shadow")
    d = s.decide("aios.secret_project_x")
    assert hashlib.sha256(b"aios.secret_project_x").hexdigest()[:12] not in s.stats()["unregistered_samples"]
    assert list(d.disagreements) == sorted(d.disagreements)


# #7: never write to stdout (the MCP JSON-RPC channel) when stderr is missing.
def test_no_stdout_when_stderr_is_missing(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stderr", None)
    s = trs.ToolRegistryService(mode="shadow")
    trs.report(s.decide("aios.mystery.task"), "aios.mystery.task", "dispatch")
    monkeypatch.setattr(sys, "stderr", sys.__stderr__)
    assert capsys.readouterr().out == ""
