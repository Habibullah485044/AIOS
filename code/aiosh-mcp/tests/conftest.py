"""Shared test fixtures for aiosh-mcp."""

import pytest


def pytest_configure(config):
    config.addinivalue_line("markers", "toolreg_watchdog: fail the test with a TimeoutError if it runs past "
                                       "AIOSH_TOOLREG_FUZZ_TIMEOUT_S (T-03420)")


@pytest.hookimpl(wrapper=True)
def pytest_runtest_call(item):
    """Run ``toolreg_watchdog`` tests under ``tool_registry_model.watchdog`` (T-03420).

    A hook, not a fixture: an exception raised in the test body never reaches a fixture, so only a call wrapper can
    turn the watchdog's interrupt into an ordinary, reported test failure.
    """
    if item.get_closest_marker("toolreg_watchdog") is None:
        return (yield)
    import tool_registry_model as M
    with M.watchdog(M.timeout_s(), what=item.nodeid):
        return (yield)


@pytest.fixture(autouse=True)
def _fresh_tool_registry_state():
    """Per-process registry state must not leak between tests.

    The registry config is resolved once per process (T-03409 #4); the service singleton, its report de-duplication
    and its one-time warnings are process-wide too (T-03419 hygiene). Tests that change env vars need fresh ones.
    """
    from aiosh_mcp import tool_registry_config, tool_registry_policy, tool_registry_service
    def reset():
        tool_registry_config.reset_process_config()
        tool_registry_service._SERVICE = None
        tool_registry_service._SERVICE_ERROR = None
        tool_registry_service._REPORTED.clear()
        tool_registry_service._REPORT_STATE.update(lines=0, suppressed=0)
        tool_registry_service._WARNED.clear()
        tool_registry_policy.reset_process_state()
    reset()
    yield
    reset()
