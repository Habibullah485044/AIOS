"""Scaffold tests for Incident Response Runbooks Automated Tests (T-03015).

Contract: docs/tasks/evidence/T-03014-spec.md.
"""

import pytest

from aiosh_mcp.incident_runbook_data_model import (
    RunbookCatalogSnapshot,
    IncidentCategory,
    IncidentSeverity,
    RUNBOOK_ERR_BOUNDS_EXCEEDED,
)
from aiosh_mcp.incident_runbook_service import (
    RunbookExecutionSession,
    RunbookExecutionStatus,
    RUNBOOK_ERR_SESSION_NOT_FOUND,
)
from aiosh_mcp.runbook_config import (
    RunbookConfig,
    resolve_runbook_config,
    safe_resolve_runbook_config,
)
from aiosh_mcp.incident_runbook_mcp import (
    execute_runbook_action,
    execute_scan_action,
)


def test_scaffold_imports_and_types_exist():
    snap = RunbookCatalogSnapshot.canonical_baseline()
    assert len(snap.runbooks) >= 2

    cfg = RunbookConfig()
    assert cfg.max_active_sessions == 1000

    assert RUNBOOK_ERR_SESSION_NOT_FOUND == "RUNBOOK_ERR_SESSION_NOT_FOUND"
    assert RUNBOOK_ERR_BOUNDS_EXCEEDED == "RUNBOOK_ERR_BOUNDS_EXCEEDED"


def stub_autorunbook_vector(vector_id: str):
    raise NotImplementedError(f"Vector {vector_id} scaffold - pending T-03016 implementation")


def test_scaffold_autorunbook_fail_loudly():
    with pytest.raises(NotImplementedError, match="pending T-03016 implementation"):
        stub_autorunbook_vector("AUTORUNBOOK1")
