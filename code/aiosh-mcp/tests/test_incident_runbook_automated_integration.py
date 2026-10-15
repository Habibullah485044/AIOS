"""Integration Tests for Incident Response Runbooks Automated Tests in FastMCP (T-03018).

Validates end-to-end MCP action dispatch, session life-cycle across tools, and
scanning action integration.
"""

from aiosh_mcp.incident_runbook_mcp import execute_runbook_action, execute_scan_action


def test_integration_mcp_runbook_lifecycle():
    # 1. Init catalog
    init_res = execute_runbook_action(action="init")
    assert init_res["ok"] is True
    assert init_res["runbooks_count"] == 2

    # 2. List runbooks
    list_res = execute_runbook_action(action="list")
    assert list_res["ok"] is True
    assert len(list_res["runbooks"]) == 2

    # 3. Show runbook
    show_res = execute_runbook_action(action="show", runbook_id="RB-IR-ACCESS-01")
    assert show_res["ok"] is True
    assert show_res["runbook"]["id"] == "RB-IR-ACCESS-01"

    # 4. Start execution session
    start_res = execute_runbook_action(
        action="start",
        runbook_id="RB-IR-ACCESS-01",
        incident_id="INC-E2E-MCP-01",
        parameters={"grant_id": "grant-bad-1", "session_id": "sess-rogue-2"},
    )
    assert start_res["ok"] is True
    sess_id = start_res["session_id"]
    assert start_res["status"] == "pending"

    # 5. Advance Step 1 (automated)
    step1_res = execute_runbook_action(action="step", session_id=sess_id)
    assert step1_res["ok"] is True
    assert step1_res["step_status"] == "completed"

    # 6. Advance Step 2 (requires confirmation -> halts with awaiting_confirmation=True)
    step2_res = execute_runbook_action(action="step", session_id=sess_id)
    assert step2_res["ok"] is False
    assert step2_res["awaiting_confirmation"] is True
    assert "RUNBOOK_ERR_MISSING_CONFIRMATION" in step2_res["error"]

    # 7. Confirm Step 2
    confirm_res = execute_runbook_action(
        action="confirm",
        session_id=sess_id,
        operator_id="soc_operator_1",
        token="GRANT-TOKEN-CONFIRM-99",
    )
    assert confirm_res["ok"] is True
    assert confirm_res["confirmed_by"] == "soc_operator_1"

    # 8. Resume Step 2 to completion
    step2_done = execute_runbook_action(action="step", session_id=sess_id)
    assert step2_done["ok"] is True
    assert step2_done["step_status"] == "completed"
    assert step2_done["status"] == "completed"

    # 9. Session status inspect
    status_res = execute_runbook_action(action="status", session_id=sess_id)
    assert status_res["ok"] is True
    assert status_res["session"]["status"] == "completed"
    assert status_res["session"]["current_step_index"] == 2


def test_integration_mcp_scan_tools():
    # Net scan
    net_res = execute_scan_action(
        action="net",
        target="127.0.0.1",
        ports="65530,65531",
    )
    assert net_res["ok"] is True
    assert net_res["scanned_ports_count"] == 2

    # Files scan
    files_res = execute_scan_action(
        action="files",
        target=".",
        pattern="aiosh",
        max_depth=1,
    )
    assert files_res["ok"] is True
    assert files_res["pattern"] == "aiosh"
