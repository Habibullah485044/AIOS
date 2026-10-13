"""Unit tests for Incident Response Runbooks & RustSec MCP surface (T-02997)."""

import os
import tempfile
import pytest

from aiosh_mcp.incident_runbook_mcp import (
    execute_runbook_action,
    execute_scan_action,
    validate_scan_target,
    SEC_ERR_INVALID_TARGET,
    SEC_ERR_BOUNDS_EXCEEDED,
    MAX_SCAN_TARGET_LEN,
)
from aiosh_mcp.incident_runbook_service import (
    RUNBOOK_ERR_SESSION_NOT_FOUND,
    RUNBOOK_ERR_MISSING_CONFIRMATION,
    RUNBOOK_ERR_INVALID_TRANSITION,
)


def test_target_validation():
    # Valid targets
    assert validate_scan_target("127.0.0.1") == "127.0.0.1"
    assert validate_scan_target("localhost") == "localhost"
    assert validate_scan_target("/var/log/audit.log") == "/var/log/audit.log"
    assert validate_scan_target("C:\\Windows\\Temp") == "C:\\Windows\\Temp"

    # Invalid targets
    with pytest.raises(ValueError, match=SEC_ERR_INVALID_TARGET):
        validate_scan_target("")

    with pytest.raises(ValueError, match=SEC_ERR_INVALID_TARGET):
        validate_scan_target("../etc/passwd")

    with pytest.raises(ValueError, match=SEC_ERR_INVALID_TARGET):
        validate_scan_target("127.0.0.1; rm -rf /")

    with pytest.raises(ValueError, match=SEC_ERR_INVALID_TARGET):
        validate_scan_target("127.0.0.1\0malicious")

    # Bounds exceeded
    oversized = "a" * (MAX_SCAN_TARGET_LEN + 1)
    with pytest.raises(ValueError, match=SEC_ERR_BOUNDS_EXCEEDED):
        validate_scan_target(oversized)


def test_runbook_mcp_list_and_show():
    res_list = execute_runbook_action(action="list")
    assert res_list["ok"] is True
    assert len(res_list["runbooks"]) >= 2

    # Filtering by category
    res_filtered = execute_runbook_action(action="list", category="malware_containment")
    assert res_filtered["ok"] is True
    assert any(rb["id"] == "RB-IR-MALWARE-01" for rb in res_filtered["runbooks"])

    res_show = execute_runbook_action(action="show", runbook_id="RB-IR-MALWARE-01")
    assert res_show["ok"] is True
    assert res_show["runbook"]["id"] == "RB-IR-MALWARE-01"
    assert len(res_show["runbook"]["steps"]) == 3


def test_runbook_mcp_session_lifecycle():
    # Start
    start_res = execute_runbook_action(
        action="start",
        runbook_id="RB-IR-MALWARE-01",
        incident_id="INC-MCP-01",
        parameters={"target_pid": "1234", "target_uid": "1001"},
    )
    assert start_res["ok"] is True
    session_id = start_res["session_id"]
    assert session_id is not None
    assert start_res["current_step_index"] == 0

    # Step 1
    step1 = execute_runbook_action(action="step", session_id=session_id)
    assert step1["ok"] is True
    assert step1["step_status"] == "completed"
    assert step1["current_step_index"] == 1

    # Status
    status_res = execute_runbook_action(action="status", session_id=session_id)
    assert status_res["ok"] is True
    assert status_res["session"]["current_step_index"] == 1
    assert status_res["session"]["steps_completed"] == 1

    # Step 2
    step2 = execute_runbook_action(action="step", session_id=session_id)
    assert step2["ok"] is True
    assert step2["current_step_index"] == 2

    # Step 3
    step3 = execute_runbook_action(action="step", session_id=session_id)
    assert step3["ok"] is True
    assert step3["status"] == "completed"

    # Advancing completed session produces error
    step_after = execute_runbook_action(action="step", session_id=session_id)
    assert step_after["ok"] is False


def test_runbook_mcp_confirmation_gating():
    # RB-IR-ACCESS-01 has step 2 requiring confirmation
    start_res = execute_runbook_action(
        action="start",
        runbook_id="RB-IR-ACCESS-01",
        incident_id="INC-MCP-CONFIRM",
        parameters={"grant_id": "tok_123", "session_id": "sess_456"},
    )
    assert start_res["ok"] is True
    session_id = start_res["session_id"]

    # Step 1: automated revocation
    s1 = execute_runbook_action(action="step", session_id=session_id)
    assert s1["ok"] is True

    # Step 2: requires confirmation
    s2 = execute_runbook_action(action="step", session_id=session_id)
    assert s2["ok"] is False
    assert s2.get("awaiting_confirmation") is True

    # Submitting confirmation
    conf = execute_runbook_action(
        action="confirm",
        session_id=session_id,
        operator_id="sec_admin",
        token="CONFIRM_OK_123",
    )
    assert conf["ok"] is True

    # Step 2 now advances successfully
    s2_retry = execute_runbook_action(action="step", session_id=session_id)
    assert s2_retry["ok"] is True


def test_runbook_mcp_abort():
    start_res = execute_runbook_action(
        action="start",
        runbook_id="RB-IR-MALWARE-01",
        incident_id="INC-MCP-ABORT",
        parameters={"target_pid": "9999", "target_uid": "1002"},
    )
    assert start_res["ok"] is True
    session_id = start_res["session_id"]

    abort_res = execute_runbook_action(action="abort", session_id=session_id, reason="False alarm")
    assert abort_res["ok"] is True
    assert abort_res["status"] == "aborted"


def test_runbook_mcp_negative_errors():
    # Show without ID
    res = execute_runbook_action(action="show")
    assert res["ok"] is False

    # Start with invalid ID
    res = execute_runbook_action(action="start", runbook_id="RB-NONEXISTENT", incident_id="INC-1")
    assert res["ok"] is False

    # Status with invalid session
    res = execute_runbook_action(action="status", session_id="INVALID-SESSION-UUID")
    assert res["ok"] is False

    # Confirm with missing token
    res = execute_runbook_action(action="confirm", session_id="INVALID-SESSION", operator_id="admin")
    assert res["ok"] is False


def test_scan_mcp_files_and_net():
    # File search
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "suspicious.log")
        with open(test_file, "w") as f:
            f.write("Line 1: clean\nLine 2: MATCH_IOC_TOKEN_XYZ payload\nLine 3: clean\n")

        res_files = execute_scan_action(
            action="files",
            target=tmpdir,
            pattern="MATCH_IOC_TOKEN",
            max_depth=3,
        )
        assert res_files["ok"] is True
        assert res_files["matches_count"] >= 1
        assert "MATCH_IOC_TOKEN_XYZ" in res_files["matches"][0]["line"]

    # Net scan (localhost probe)
    res_net = execute_scan_action(
        action="net",
        target="127.0.0.1",
        ports="80,443,65534",
        timeout_ms=50,
    )
    assert res_net["ok"] is True
    assert res_net["scanned_ports_count"] == 3
    assert res_net["target"] == "127.0.0.1"


def test_scan_mcp_web_probing():
    # Web probing on localhost
    res_web = execute_scan_action(
        action="web",
        target="127.0.0.1:9",
        wordlist="admin,metrics",
        timeout_ms=50,
    )
    assert res_web["ok"] is True
    assert res_web["probed_count"] == 2
