"""Hardening of the tool registry automated tests themselves (T-03420).

The property suite is a safety net, so it must not be able to hang, run unbounded, or fail in a way that is hard to
read. Every knob is bounded and named in its error. A hung property is failed with its location. The Rust drift
parser fails loudly on any pep.rs it was not written for. Config-file handles are released after every read.
"""

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

import tool_registry_model as M
import test_tool_registry_rust_drift as D
from aiosh_mcp import tool_registry_config as conf

TESTS = Path(__file__).resolve().parent
PKG = TESTS.parent


# ---- knobs: bounded, and the error names the variable -----------------------------------------------------------

@pytest.mark.parametrize("var,value,fn", [
    ("AIOSH_TOOLREG_FUZZ_SEEDS", "1,x", M.seeds),
    ("AIOSH_TOOLREG_FUZZ_N", "ten", M.n_cases),
    ("AIOSH_TOOLREG_FUZZ_N", "1e3", M.n_cases),
    ("AIOSH_TOOLREG_FUZZ_TIMEOUT_S", "soon", M.timeout_s),
])
def test_non_numeric_knob_names_the_variable(var, value, fn, monkeypatch):
    monkeypatch.setenv(var, value)
    with pytest.raises(ValueError, match=var):
        fn()


def test_seed_count_is_capped(monkeypatch):
    monkeypatch.setenv("AIOSH_TOOLREG_FUZZ_SEEDS", ",".join(str(i) for i in range(M.MAX_SEEDS)))
    assert len(M.seeds()) == M.MAX_SEEDS
    monkeypatch.setenv("AIOSH_TOOLREG_FUZZ_SEEDS", ",".join(str(i) for i in range(M.MAX_SEEDS + 1)))
    with pytest.raises(ValueError, match="at most"):
        M.seeds()


def test_case_count_is_capped(monkeypatch):
    monkeypatch.setenv("AIOSH_TOOLREG_FUZZ_N", str(M.MAX_CASES))
    assert M.n_cases() == M.MAX_CASES
    monkeypatch.setenv("AIOSH_TOOLREG_FUZZ_N", str(M.MAX_CASES + 1))
    with pytest.raises(ValueError, match="cap"):
        M.n_cases()


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf", str(M.MAX_TIMEOUT_S + 1)])
def test_timeout_must_be_positive_and_bounded(value, monkeypatch):
    monkeypatch.setenv("AIOSH_TOOLREG_FUZZ_TIMEOUT_S", value)
    with pytest.raises(ValueError, match="AIOSH_TOOLREG_FUZZ_TIMEOUT_S"):
        M.timeout_s()


def test_timeout_default(monkeypatch):
    monkeypatch.delenv("AIOSH_TOOLREG_FUZZ_TIMEOUT_S", raising=False)
    assert M.timeout_s() == M.DEFAULT_TIMEOUT_S


# ---- watchdog: a hang becomes a reported failure ----------------------------------------------------------------

def _child(body: str, timeout: float = 60) -> subprocess.CompletedProcess:
    code = f"import sys, time; sys.path.insert(0, {str(TESTS)!r}); import tool_registry_model as M\n{body}"
    return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=timeout,
                          cwd=str(PKG))


def test_python_level_hang_becomes_a_timeout_error():
    started = time.monotonic()
    p = _child("def spin():\n    while True:\n        pass\nwith M.watchdog(1, what='busy', grace=20):\n    spin()\n")
    assert time.monotonic() - started < 20, "soft stage did not fire"
    assert p.returncode != 0
    assert "TimeoutError: busy ran longer than 1s" in p.stderr
    assert ", in spin" in p.stderr                                 # the traceback points at the hung code


def test_hang_the_interrupt_cannot_reach_is_killed_with_stacks():
    # A long sleep may not be woken by the simulated interrupt; the hard stage must still end the process.
    started = time.monotonic()
    p = _child("with M.watchdog(1, what='stuck', grace=2):\n    time.sleep(40)\n")
    assert time.monotonic() - started < 30
    assert p.returncode != 0
    assert "TimeoutError" in p.stderr or "Timeout" in p.stderr      # soft stage, or faulthandler's "Timeout (0:00:03)!"


def test_watchdog_is_cancelled_when_the_block_ends():
    p = _child("with M.watchdog(1, what='fast', grace=1):\n    pass\ntime.sleep(3)\nprint('alive')\n")
    assert p.returncode == 0, p.stderr
    assert p.stdout.strip() == "alive"


def test_watchdog_lets_other_errors_through():
    p = _child("with M.watchdog(5, what='x', grace=5):\n    raise KeyError('boom')\n")
    assert p.returncode != 0 and "KeyError: 'boom'" in p.stderr and "TimeoutError" not in p.stderr


def test_pytest_reports_a_hung_marked_test_and_keeps_going(tmp_path):
    """End to end through conftest's call wrapper: the hung test fails with TimeoutError, the next test still runs."""
    (tmp_path / "test_hang.py").write_text(
        "import pytest\n\n"
        "@pytest.mark.toolreg_watchdog\n"
        "def test_spins():\n"
        "    while True:\n"
        "        pass\n\n"
        "def test_after():\n"
        "    assert True\n", encoding="utf-8")
    env = dict(os.environ, AIOSH_TOOLREG_FUZZ_TIMEOUT_S="1",
               PYTHONPATH=os.pathsep.join([str(TESTS), str(PKG), os.environ.get("PYTHONPATH", "")]))
    started = time.monotonic()
    p = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "conftest",
                        str(tmp_path / "test_hang.py")], capture_output=True, text=True, timeout=120,
                       cwd=str(tmp_path), env=env)
    assert time.monotonic() - started < 60
    out = p.stdout + p.stderr
    assert p.returncode == 1, out                                     # 1 = tests failed (2 would be "interrupted")
    assert "1 failed, 1 passed" in out and "TimeoutError" in out, out


def test_property_module_is_under_the_watchdog():
    import test_tool_registry_properties as P
    marks = P.pytestmark if isinstance(P.pytestmark, list) else [P.pytestmark]
    assert any(m.name == "toolreg_watchdog" for m in marks)


# ---- Rust drift parser: every unexpected shape fails with its reason --------------------------------------------

_OK = 'pub fn is_irreversible(tool: &str) -> bool {\n    if tool == "a" { return false; }\n    tool == "x"\n}\n'


@pytest.mark.parametrize("text,reason", [
    ("fn other() {}\n", "exactly once, found 0"),
    (_OK + _OK, "exactly once, found 2"),
    ('pub fn is_irreversible(tool: &str) -> bool {\n    tool == "x"\n', "closing brace"),
    ('pub fn is_irreversible(tool: &str) -> bool {\n    tool == "x"\n}\n', "found 0"),
    ('pub fn is_irreversible(tool: &str) -> bool {\n    if tool == "a" { return false; }\n'
     '    if tool == "b" { return false; }\n    tool == "x"\n}\n', "found 2"),
])
def test_drift_parser_refuses_unexpected_shapes(tmp_path, text, reason):
    path = tmp_path / "pep.rs"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(AssertionError, match=reason):
        D.rust_rule(path)


def test_drift_parser_accepts_the_minimal_shape(tmp_path):
    path = tmp_path / "pep.rs"
    path.write_text(_OK, encoding="utf-8")
    rule, (not_exact, _, exact, _) = D.rust_rule(path)
    assert not_exact == {"a"} and exact == {"x"} and rule("x") and not rule("a")


def test_drift_parser_refuses_missing_and_oversize_files(tmp_path):
    with pytest.raises(AssertionError, match="needs"):
        D.rust_rule(tmp_path / "absent.rs")
    big = tmp_path / "big.rs"
    big.write_bytes(_OK.encode() + b"/" * (D.MAX_PEP_RS_BYTES + 1))
    with pytest.raises(AssertionError, match="cap"):
        D.rust_rule(big)


# ---- cleanup: config reads leave no open handle ------------------------------------------------------------------

def test_config_reads_release_the_file(tmp_path, monkeypatch):
    """On Windows an open handle makes ``unlink`` fail, so deleting right after each read proves the handle is gone.
    The loop also catches a slow leak that a single read would not show."""
    cfg = tmp_path / "c.json"
    monkeypatch.setenv(conf.ENV_CONFIG, str(cfg))
    fds_before = len(os.listdir("/proc/self/fd")) if os.path.isdir("/proc/self/fd") else None
    for case in range(50):
        cfg.write_text('{"mode": "strict", "report_max_lines": 64}' if case % 2 else "{not json", encoding="utf-8")
        conf.resolve()
        cfg.unlink()                                                    # PermissionError here = leaked handle
    if fds_before is not None:
        assert len(os.listdir("/proc/self/fd")) <= fds_before + 1
