"""Cross-substrate automated test: TS issuer -> Python redeemer on one ring (T-03318; spec T-03314 §4).

Automates the by-hand check from T-03291. Skips with a stated reason (never a silent pass)
when node or the built TS CLI is unavailable.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from agent_loop_grants import verify_chain
from aiosh_mcp.agent_loop_data_model import LoopConfig
from aiosh_mcp.agent_loop_gate import PepCapabilityGate, read_loop_history
from aiosh_mcp.agent_loop_service import AgentLoopService, AgentLoopServiceError

REPO = Path(__file__).resolve().parents[3]
TS_CLI = REPO / "code" / "aiosh-cli" / "dist" / "cli.js"
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(
    NODE is None or not TS_CLI.is_file(),
    reason=f"cross-substrate test needs node ({NODE or 'missing'}) and a built TS CLI at {TS_CLI} (npm run build)",
)


def ts_grant(home: Path, tools: str, ttl: int = 600) -> str:
    out = subprocess.run([NODE, str(TS_CLI), "grant", "create", "--to", "agent:planner", "--tools", tools,
                          "--ttl", str(ttl)], env=dict(os.environ, AIOSH_HOME=str(home)),
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)["data"]["grant_id"]


def test_ts_issued_grant_drives_python_loop(tmp_path):
    grant = ts_grant(tmp_path, "aios.agent_loop.start,aios.fs.read")
    db = str(tmp_path / "audit.db")
    svc = AgentLoopService(gate=PepCapabilityGate(db))
    svc.start_loop(LoopConfig(loop_id="loop-xsub-01"), capability_token=grant)
    ok = svc.advance_turn("loop-xsub-01", "read", tool_name="aios.fs.read", capability_token=grant)
    no = svc.advance_turn("loop-xsub-01", "write", tool_name="fs.write", capability_token=grant)
    assert (ok.outcome, no.outcome) == ("ok", "refused")
    svc.complete_loop("loop-xsub-01", capability_token=grant)

    assert [e["tool"] for e in read_loop_history(db, "loop-xsub-01", 100)] == [
        "aios.agent_loop.start", "aios.agent_loop.step", "aios.agent_loop.step", "aios.agent_loop.complete"]
    assert verify_chain(db).get("ok") is True  # TS (grant.create) and Python rows share one chain


def test_ts_scope_and_single_use_are_honoured_by_python(tmp_path):
    db = str(tmp_path / "audit.db")
    narrow = ts_grant(tmp_path, "aios.fs.read")  # cannot start loops
    with pytest.raises(AgentLoopServiceError) as exc:
        AgentLoopService(gate=PepCapabilityGate(db)).start_loop(LoopConfig(loop_id="loop-xsub-02"),
                                                                capability_token=narrow)
    assert exc.value.code == "LOOPSERV_ERR_UNAUTHORIZED"

    once = ts_grant(tmp_path, "aios.agent_loop.start")
    AgentLoopService(gate=PepCapabilityGate(db)).start_loop(LoopConfig(loop_id="loop-xsub-03"), capability_token=once)
    with pytest.raises(AgentLoopServiceError) as exc:
        AgentLoopService(gate=PepCapabilityGate(db)).start_loop(LoopConfig(loop_id="loop-xsub-04"),
                                                                capability_token=once)
    assert "already redeemed" in exc.value.message
