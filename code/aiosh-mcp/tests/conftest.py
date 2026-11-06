"""Shared test fixtures for aiosh-mcp."""

import pytest


@pytest.fixture(autouse=True)
def _fresh_tool_registry_config():
    """The registry config is resolved once per process (T-03409 #4); tests that change env vars need a fresh one."""
    from aiosh_mcp import tool_registry_config
    tool_registry_config.reset_process_config()
    yield
    tool_registry_config.reset_process_config()
