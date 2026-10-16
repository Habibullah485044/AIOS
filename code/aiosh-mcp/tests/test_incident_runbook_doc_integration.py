"""Integration tests for Incident Response Runbooks Documentation Subsystem (T-03048)."""

from aiosh_mcp.incident_runbook_mcp import execute_runbook_action


def test_integration_doc_fastmcp_lifecycle():
    # 1. doc_list through execute_runbook_action (includes audit gate)
    res_list = execute_runbook_action(action="doc_list")
    assert res_list["ok"] is True
    assert res_list["action"] == "doc_list"
    assert "audit_id" in res_list
    assert len(res_list["topics"]) >= 7

    # 2. doc_get through audit gate
    res_get = execute_runbook_action(action="doc_get", runbook_id="runbook.tools.scanning")
    assert res_get["ok"] is True
    assert res_get["action"] == "doc_get"
    assert "audit_id" in res_get
    assert res_get["topic"]["category"] == "security_tools"

    # 3. doc_search through audit gate
    res_search = execute_runbook_action(
        action="doc_search",
        parameters={"query": "RustSec"},
    )
    assert res_search["ok"] is True
    assert res_search["action"] == "doc_search"
    assert "audit_id" in res_search
    assert len(res_search["results"]) > 0
    assert any(r["topic_id"] == "runbook.tools.scanning" for r in res_search["results"])
