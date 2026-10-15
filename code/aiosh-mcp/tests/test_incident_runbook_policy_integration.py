"""Integration tests for Incident Response Runbooks Security Policy in FastMCP (T-03028)."""

from aiosh_mcp.incident_runbook_mcp import execute_runbook_action, execute_scan_action
from aiosh_mcp.incident_runbook_policy import (
    RUNBOOKPOL_ERR_CATEGORY_DISALLOWED,
    RUNBOOKPOL_ERR_SCAN_BOUNDS,
)


def test_integration_mcp_policy_inspection():
    res = execute_runbook_action(action="policy")
    assert res["ok"] is True
    assert res["action"] == "policy"
    assert res["mode"] == "enforcing"
    assert res["require_operator_confirmation_for_high_risk"] is True
    assert res["max_step_timeout_seconds"] == 60


def test_integration_mcp_policy_scan_budget_enforcement():
    # Attempting to scan exceeding max policy ports
    huge_ports = ",".join(str(i) for i in range(1, 10005))
    res = execute_scan_action(action="net", target="127.0.0.1", ports=huge_ports)
    assert res["ok"] is False
    assert RUNBOOKPOL_ERR_SCAN_BOUNDS in res["error"]
