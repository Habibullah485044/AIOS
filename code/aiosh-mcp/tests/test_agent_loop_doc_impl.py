"""Implementation tests for the agent-loop generated reference (T-03346; spec T-03344)."""

import json

import pytest

from agent_loop_grants import AllowAllGate
from aiosh_mcp import agent_loop_config as cfg
from aiosh_mcp import agent_loop_doc as doc
from aiosh_mcp.agent_loop_data_model import LoopConfig, LoopState
from aiosh_mcp.agent_loop_mcp import TOOL_ANNOTATIONS
from aiosh_mcp.agent_loop_service import LOOPSERV_ERR_CIRCUIT_BREAKER, AgentLoopService
from aiosh_mcp.server import mcp


def test_all_sections_present_and_derived_from_code():
    r = doc.reference()
    assert set(r) == set(doc.SECTIONS)
    assert {t["name"] for t in r["tools"]} == set(TOOL_ANNOTATIONS)
    assert {e["code"] for e in r["errors"]} == set(doc.ERROR_MEANINGS)
    assert all(e["meaning"] for e in r["errors"])
    assert [f["key"] for f in r["config"]["fields"]] == list(cfg.FIELDS)
    assert {c["subcommand"] for c in r["cli"]} == {"validate", "run", "history", "config", "metrics"}
    assert r["policy"]["order"][1] == "P2 constitution classifier"


def test_tool_schemas_match_the_live_server():
    live = {t.name: t.parameters for t in mcp._tool_manager.list_tools() if t.name in TOOL_ANNOTATIONS}
    ref = {t["name"]: t["input_schema"] for t in doc.reference("tools")["tools"]}
    assert ref == live
    adv = next(t for t in doc.reference("tools")["tools"] if t["name"] == "aios_agent_loop_advance")
    assert adv["annotations"]["readOnlyHint"] is False


def test_single_section_and_unknown_section():
    assert list(doc.reference("config")) == ["config"]
    with pytest.raises(ValueError):
        doc.reference("secrets")


def test_reference_contains_no_environment_values(monkeypatch, tmp_path):
    marker = "SENTINEL-HOME-7f3a"
    monkeypatch.setenv("AIOSH_HOME", str(tmp_path / marker))
    monkeypatch.setenv("AIOSH_AGENT_LOOP_REGISTRY_CAPACITY", "7")
    text = json.dumps(doc.reference(), default=str)
    assert marker not in text
    assert "AIOSH_AGENT_LOOP_REGISTRY_CAPACITY" in text      # env variable *names* are documented
    assert '"default": 256' in text                           # defaults, not the env override


def test_circuit_breaker_code_on_terminal_reason():
    svc = AgentLoopService(gate=AllowAllGate())
    svc.start_loop(LoopConfig(loop_id="loop-doc-cb-01", max_iterations=1), capability_token="t")
    svc.advance_turn("loop-doc-cb-01", "only", capability_token="t")
    snap = svc.get_snapshot("loop-doc-cb-01")
    assert snap.current_state == LoopState.FAILED
    assert snap.terminal_reason.startswith(f"{LOOPSERV_ERR_CIRCUIT_BREAKER}: Iteration limit reached")
    svc.start_loop(LoopConfig(loop_id="loop-doc-cb-02"), capability_token="t")
    svc.abort_loop("loop-doc-cb-02", "operator stop", capability_token="t")
    assert svc.get_snapshot("loop-doc-cb-02").terminal_reason == "operator stop"   # aborts are not breakers
