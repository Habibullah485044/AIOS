"""Implementation tests for the tool registry core service (T-03376; spec T-03374)."""

import json
import random
import string

import pytest

from aiosh_mcp import tool_registry_service as svc
from aiosh_mcp.agent_loop_policy import is_irreversible
from aiosh_mcp.tool_registry_data_model import ScopeKind, default_catalog
from aiosh_mcp.tool_registry_service import ToolRegistryService, ToolServiceError


def legacy_grant(tool):                         # audit_client.grant_check's irreversible set
    return tool.startswith("pentest.") or tool.startswith("fs.write") or tool in ("system.reboot", "system.shutdown")


def legacy_scope(tool):
    return ScopeKind.NETWORK if tool.startswith(("pentest.", "network.")) else ScopeKind.PATH


S = ToolRegistryService(mode="shadow")


def test_registered_tool_agrees():
    d = S.decide("pentest.nmap", "10.0.0.5")
    assert (d.canonical, d.registered, d.requires_grant, d.irreversible) == ("pentest.nmap", True, True, True)
    assert d.scope_kinds == (ScopeKind.NETWORK,) and d.disagreements == () and d.mode == "shadow"
    assert S.decide("aios_pentest_nmap").canonical == "pentest.nmap"        # MCP alias resolves


def test_fs_read_grant_needs_the_caller_flag_to_agree():
    assert S.decide("aios.fs.read", "/tmp/x", require_grant=True).disagreements == ()
    assert S.decide("aios.fs.read", "/tmp/x").disagreements == ("grant",)    # catalog is stricter than grant_check


def test_offline_pentest_tools_get_both_scopes():
    d = S.decide("pentest.tshark", "/tmp/cap.pcap")
    assert set(d.scope_kinds) == {ScopeKind.PATH, ScopeKind.NETWORK} and d.disagreements == ("scope",)


def test_unregistered_names_fail_closed_and_are_reported():
    d = S.decide("aios.mystery.tool")
    assert d.registered is False and d.requires_grant and d.irreversible
    assert "unregistered" in d.disagreements
    for odd in (None, 7, b"x", "", "\x00" * 3):
        o = S.decide(odd)
        assert o.registered is False and o.requires_grant and o.irreversible


def test_classifier_c3_makes_a_call_irreversible():
    d = S.decide("aios.fs.read", "/tmp/x", classification={"c_flags": {"c3": True}}, require_grant=True)
    assert d.irreversible is True


# TOOLSVC-INV1: never weaker than the legacy rules, for every registered name and random names.
def _corpus():
    rng = random.Random(3376)
    names = [n for n in default_catalog().names()]
    names += ["process.kill", "shell.exec", "fs.write_x", "system.reboot", "network.probe", "PENTEST.X", "pentest"]
    alphabet = string.ascii_lowercase + "._-" + "PSN"
    names += ["".join(rng.choice(alphabet) for _ in range(rng.randint(1, 20))) for _ in range(500)]
    return names


@pytest.mark.parametrize("require_grant", [False, True])
def test_never_weaker_than_legacy(require_grant):
    for name in _corpus():
        d = S.decide(name, "t", require_grant=require_grant)
        assert d.requires_grant >= (legacy_grant(name) or require_grant), name
        assert d.irreversible >= is_irreversible(name, {}), name
        assert legacy_scope(name) in d.scope_kinds, name


def test_modes():
    assert S.enforcement(S.decide("aios.mystery.tool")) == {}                 # shadow enforces nothing new
    strict = ToolRegistryService(mode="strict")
    e = strict.enforcement(strict.decide("pentest.tshark", "/tmp/c"))
    assert e == {"requires_grant": True, "irreversible": True, "scope_kinds": ("network", "path")}
    with pytest.raises(ToolServiceError) as exc:
        ToolRegistryService(mode="enforce")
    assert exc.value.code == "TOOLSVC_ERR_MODE"


def test_mode_from_env(monkeypatch):
    from aiosh_mcp.tool_registry_config import reset_process_config
    monkeypatch.setenv(svc.ENV_MODE, "strict")
    assert ToolRegistryService().decide("pentest.nmap").mode == "strict"
    monkeypatch.setenv(svc.ENV_MODE, "bogus")
    reset_process_config()                                         # config is resolved once per process (T-03409)
    assert ToolRegistryService().mode == "strict"                  # unrecognised env value fails closed (T-03379)
    monkeypatch.delenv(svc.ENV_MODE)
    reset_process_config()
    assert ToolRegistryService().decide("pentest.nmap").mode == "shadow"


def test_stats_are_bounded(monkeypatch):
    s = ToolRegistryService(mode="shadow")
    for i in range(500):
        s.decide(f"aios.unknown.t{i}")
    s.decide("pentest.nmap")
    st = s.stats()
    assert st["decisions"] == 501 and st["unregistered"] == 500
    assert st["disagreements"]["unregistered"] == 500
    assert len(st["unregistered_samples"]) == svc.MAX_UNREGISTERED_SAMPLES
    assert all(len(h) == 12 and "unknown" not in h for h in st["unregistered_samples"])   # hashed, not raw


@pytest.fixture
def fresh_reports(monkeypatch):
    monkeypatch.setattr(svc, "_REPORTED", set())
    monkeypatch.setattr(svc, "_REPORT_STATE", {"lines": 0, "suppressed": 0})


def test_report_writes_one_masked_stderr_line(capsys, fresh_reports):
    d = S.decide("pentest.tshark", "/tmp/c")
    svc.report(d, "aios.x.sk-" + "a" * 30, surface="dispatch")
    err = capsys.readouterr().err.strip().splitlines()
    assert len(err) == 1
    line = json.loads(err[0])
    assert line["event"] == svc.LOG_EVENT and line["disagreements"] == ["scope"] and line["surface"] == "dispatch"
    assert "sk-aaaa" not in err[0] and len(line["tool"]) <= 64
    svc.report(S.decide("pentest.nmap"), "pentest.nmap", surface="dispatch")       # agreement: nothing logged
    assert capsys.readouterr().err == ""


def test_service_singleton():
    assert svc.service() is svc.service()
