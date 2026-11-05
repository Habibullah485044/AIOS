"""Unit tests for the tool registry core service (T-03377; spec T-03374).

Boundaries, malformed inputs (decide never raises), concurrency of the counters, and the logging edge cases.
"""

import io
import json
import sys
import threading

import pytest

from aiosh_mcp import tool_registry_service as svc
from aiosh_mcp.tool_registry_data_model import ScopeKind, ToolCatalog
from aiosh_mcp.tool_registry_service import ToolRegistryService, ToolServiceError


@pytest.mark.parametrize("classification", [None, {}, [], "c3", 7, {"c_flags": None}, {"c_flags": []},
                                            {"c_flags": "c3"}, {"c_flags": {"c3": "yes"}}, {"c_flags": {"c3": 0}}])
def test_decide_never_raises_on_malformed_classification(classification):
    d = ToolRegistryService(mode="shadow").decide("aios.fs.read", "/tmp/x", classification=classification,
                                                  require_grant=True)
    assert d.registered is True


def test_only_a_real_c3_flag_marks_irreversible():
    s = ToolRegistryService(mode="shadow")
    assert s.decide("aios.fs.read", classification={"c_flags": {"c3": True}}).irreversible is True
    assert s.decide("aios.fs.read", classification={"c_flags": {"c3": False}}).irreversible is False
    assert s.decide("aios.fs.read", classification=["c3"]).irreversible is False


@pytest.mark.parametrize("mode,ok", [("shadow", True), ("strict", True), (" STRICT ", True), ("Shadow", True),
                                     ("", False), ("off", False), ("enforce", False), (None, True), (1, False)])
def test_mode_boundaries(mode, ok, monkeypatch):
    monkeypatch.delenv(svc.ENV_MODE, raising=False)
    if ok:
        assert ToolRegistryService(mode=mode).mode in svc.MODES
    else:
        with pytest.raises(ToolServiceError) as exc:
            ToolRegistryService(mode=mode)
        assert exc.value.code == "TOOLSVC_ERR_MODE"


def test_empty_catalog_makes_everything_unregistered_and_fail_closed():
    s = ToolRegistryService(catalog=ToolCatalog([]), mode="shadow")
    d = s.decide("aios.fs.read")
    assert (d.registered, d.requires_grant, d.irreversible) == (False, True, True)


def test_scope_none_entries_keep_the_legacy_scope():
    d = ToolRegistryService(mode="shadow").decide("aios.process.list", target="x")
    assert d.scope_kinds == (ScopeKind.PATH,) and "scope" not in d.disagreements


def test_counters_are_exact_under_concurrency():
    s = ToolRegistryService(mode="shadow")
    old_interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)                    # switch threads constantly so an unlocked += would lose updates
    try:
        def work():
            for i in range(2000):
                s.decide("pentest.nmap" if i % 2 else f"aios.u.n{i}")

        threads = [threading.Thread(target=work) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        sys.setswitchinterval(old_interval)
    st = s.stats()
    assert st["decisions"] == 32000 and st["unregistered"] == 16000 and st["disagreements"]["unregistered"] == 16000
    assert len(st["unregistered_samples"]) == svc.MAX_UNREGISTERED_SAMPLES
    assert len(set(st["unregistered_samples"])) == len(st["unregistered_samples"])          # deduplicated


def test_stats_returns_copies():
    s = ToolRegistryService(mode="shadow")
    s.decide("aios.u.x")
    st = s.stats()
    st["disagreements"]["unregistered"] = 999
    st["unregistered_samples"].append("forged")
    assert s.stats()["disagreements"]["unregistered"] == 1 and "forged" not in s.stats()["unregistered_samples"]


def test_report_survives_a_closed_stderr(monkeypatch, fresh_reports):
    closed = io.StringIO()
    closed.close()
    monkeypatch.setattr(sys, "stderr", closed)
    svc.report(ToolRegistryService(mode="shadow").decide("aios.u.x"), "aios.u.x", surface="dispatch")   # no raise


@pytest.fixture
def fresh_reports(monkeypatch):
    monkeypatch.setattr(svc, "_REPORTED", set())
    monkeypatch.setattr(svc, "_REPORT_STATE", {"lines": 0, "suppressed": 0})


def test_report_masks_and_bounds_hostile_tool_names(capsys, fresh_reports):
    s = ToolRegistryService(mode="shadow")
    hostile = "ghp_" + "A" * 40 + "\n{\"event\":\"forged\"}" + "x" * 500
    svc.report(s.decide(hostile), hostile, surface="dispatch")
    lines = capsys.readouterr().err.strip().splitlines()
    assert len(lines) == 1                                         # the newline cannot inject a second line
    line = json.loads(lines[0])
    assert "AAAA" not in lines[0] and len(line["tool"]) <= svc.MAX_LOGGED_TOOL_LEN
    svc.report(s.decide(None), None, surface="dispatch")
    assert json.loads(capsys.readouterr().err)["tool"] == "<class 'NoneType'>"


def test_strict_enforcement_only_tightens():
    strict = ToolRegistryService(mode="strict")
    for name in ("aios.fs.read", "pentest.nmap", "aios.u.x", "aios.agent_loop.start"):
        d = strict.decide(name, "t")
        e = strict.enforcement(d)
        assert e["requires_grant"] is d.requires_grant and e["irreversible"] is d.irreversible
        assert set(e["scope_kinds"]) == {s.value for s in d.scope_kinds}
