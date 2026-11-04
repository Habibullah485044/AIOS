"""Regression tests for security audit finding #3 (2026-11-05): grant scope enforcement."""

import pytest

from agent_loop_grants import mint_grant
from aiosh_mcp import audit_client
from aiosh_mcp.agent_loop_data_model import LoopConfig
from aiosh_mcp.agent_loop_gate import PepCapabilityGate
from aiosh_mcp.agent_loop_service import AgentLoopService, AgentLoopServiceError, LOOPSERV_ERR_INVALID_INPUT


@pytest.mark.parametrize("tool,globs,expected", [
    ("git.push", ["git.*"], True),
    ("git", ["git.*"], True),
    ("github.delete_repo", ["git.*"], False),
    ("aios.fs_admin.wipe", ["aios.fs.*"], False),
    ("aios.fs.read", ["aios.fs.*"], True),
    ("pentest.nmap", ["pentest.*"], True),
    ("fs.write", ["fs.read"], False),
])
def test_tool_glob_respects_segment_boundary(tool, globs, expected):
    assert audit_client.tool_glob_match(tool, globs) is expected


@pytest.mark.parametrize("target,expected", [
    ("/tmp/work/a.txt", True),
    ("/tmp/../etc/passwd", False),
    ("/tmp/x/../../etc/passwd", False),
    ("C:\tmp\..\Windows\system32", False),
    ("/etc/passwd", False),
])
def test_path_allowed_refuses_dotdot(target, expected):
    assert audit_client.path_allowed(target, {"allow": ["/tmp", "C:\tmp"], "deny": []}) is expected


@pytest.fixture
def svc(tmp_path):
    db = str(tmp_path / "audit.db")
    import json, datetime as dt
    from contextlib import closing
    mint_grant(db, "gr_scope", tools=["aios.agent_loop.start", "fs.*", "network.*"])
    with closing(audit_client.open_db(db)) as conn:
        conn.execute("UPDATE pep_grants SET scope_json = ? WHERE grant_id = 'gr_scope'", (json.dumps({
            "tools": ["aios.agent_loop.start", "fs.*", "network.*"],
            "paths": {"allow": ["/tmp"], "deny": []}, "networks": ["10.0.0.0/24"]}),))
        conn.commit()
    s = AgentLoopService(gate=PepCapabilityGate(db))
    s.start_loop(LoopConfig(loop_id="loop-scope-sec-01", max_iterations=20), capability_token="gr_scope")
    return s


@pytest.mark.parametrize("tool,args,outcome", [
    ("fs.write", {"path": "/tmp/out.txt"}, "ok"),
    ("fs.write", {"path": "/etc/passwd"}, "refused"),
    ("fs.write", {"path": "/tmp/../etc/passwd"}, "refused"),
    ("network.scan", {"target": "10.0.0.7"}, "ok"),
    ("network.scan", {"target": "8.8.8.8"}, "refused"),
    ("fs.read", {"note": "no target key"}, "ok"),
])
def test_loop_step_enforces_paths_and_networks(svc, tool, args, outcome):
    step = svc.advance_turn("loop-scope-sec-01", "x", tool_name=tool, tool_args=args, capability_token="gr_scope")
    assert step.outcome == outcome, step.error_message


def test_tool_args_without_tool_rejected(svc):
    with pytest.raises(AgentLoopServiceError) as exc:
        svc.advance_turn("loop-scope-sec-01", "x", tool_args={"path": "/etc/passwd"}, capability_token="gr_scope")
    assert exc.value.code == LOOPSERV_ERR_INVALID_INPUT
