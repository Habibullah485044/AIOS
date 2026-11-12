"""Shared test fixtures for aiosh-mcp."""

import pytest


@pytest.fixture(autouse=True)
def _fresh_tool_registry_state():
    """Per-process registry state must not leak between tests.

    The registry config is resolved once per process (T-03409 #4); the service singleton, its report de-duplication
    and its one-time warnings are process-wide too (T-03419 hygiene). Tests that change env vars need fresh ones.
    """
    from aiosh_mcp import tool_registry_config, tool_registry_service
    def reset():
        tool_registry_config.reset_process_config()
        tool_registry_service._SERVICE = None
        tool_registry_service._SERVICE_ERROR = None
        tool_registry_service._REPORTED.clear()
        tool_registry_service._REPORT_STATE.update(lines=0, suppressed=0)
        tool_registry_service._WARNED.clear()
    reset()
    yield
    reset()
