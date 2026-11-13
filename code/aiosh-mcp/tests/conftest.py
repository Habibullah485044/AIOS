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


# ---- T-03429 F1: capability tokens are real PEP grants ---------------------------------------------------------
#: Grant ids the model-backend and MCP-recovery tests already pass as their "valid" capability token. Since T-03429
#: the token is redeemed against ``pep_grants``, so these tests get the grants minted (multi-use, because a test may
#: reuse its token across calls) in an isolated AIOSH_HOME. Single-use, scope, expiry and revocation are pinned by
#: tests/test_capability_redeem_security.py.
SEEDED_CAPABILITY_TOKENS = (
    "cap-token-integ-1", "cap-token-integ-2", "cap_cleanup_test_token", "cap_por_model_complete_001",
    "cap_por_model_register_001", "cap_test_token_valid", "cap_valid_integration_token", "cap_valid_token_12345",
    "grant-token-123", "por_cap_grant_repair_001", "token:valid-token-123", "valid-grant", "valid-token",
    "valid-token-123", "token:admin-grant-12345",
)
CAPABILITY_TOOLS = ("aios.model.complete", "aios.model.endpoint.register", "model_backend.complete",
                    "model_backend.register", "aios.mcp.recovery.repair", "aios.model.recover_config")
_SEEDED_MODULE_PREFIXES = ("test_model_backend_adapters_", "test_mcp_server_core_recovery_")


@pytest.fixture(autouse=True)
def _seeded_capabilities(request, tmp_path_factory, monkeypatch):
    if not request.module.__name__.rsplit(".", 1)[-1].startswith(_SEEDED_MODULE_PREFIXES):
        yield
        return
    from agent_loop_grants import mint_grant
    home = tmp_path_factory.mktemp("aiosh_home")
    monkeypatch.setenv("AIOSH_HOME", str(home))
    db = str(home / "audit.db")
    for token in SEEDED_CAPABILITY_TOKENS:
        mint_grant(db, token, tools=CAPABILITY_TOOLS, single_use=False)
    yield
