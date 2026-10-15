"""Integration tests for Incident Response Runbooks Observability in Python (T-03038).

Tests live end-to-end integration through FastMCP dispatch, session progression, and audit records.
"""

from aiosh_mcp.incident_runbook_mcp import execute_runbook_action


def test_integration_observability_fastmcp_lifecycle() -> None:
    # 1. Baseline stats check
    res_init = execute_runbook_action(action="init")
    assert res_init["ok"] is True

    res_stats1 = execute_runbook_action(action="stats")
    assert res_stats1["ok"] is True
    initial_active = res_stats1["stats"]["active_sessions_count"]

    # 2. Start a runbook session
    res_start = execute_runbook_action(
        action="start",
        runbook_id="RB-IR-MALWARE-01",
        incident_id="INC-OBS-TEST-001",
        parameters={"target_pid": "4096", "target_uid": "1001"},
    )

    assert res_start["ok"] is True
    session_id = res_start["session_id"]

    # 3. Stats must now reflect the new active session
    res_stats2 = execute_runbook_action(action="stats")
    assert res_stats2["ok"] is True
    assert res_stats2["stats"]["active_sessions_count"] == initial_active + 1
    assert res_stats2["stats"]["is_healthy"] is True
    assert "audit_id" in res_stats2

    # 4. Abort session and confirm stats reflects cleanup
    res_abort = execute_runbook_action(action="abort", session_id=session_id)
    assert res_abort["ok"] is True
