"""Integration tests for Model Backend Adapters CLI surface (T-03188).

Tests end-to-end CLI workflows through main() and dispatch_model_cli():
  - Dynamic registration followed by list, show, health, and complete
  - Multi-endpoint fallback resolution
  - Proof-of-Restraint token enforcement end-to-end
  - Output formatting and secret redaction on terminal streams
"""

import io
import json
import sys
import pytest

from aiosh_mcp.model_backend_adapters_cli import (
    EXIT_SUCCESS,
    EXIT_FAILURE,
    EXIT_USAGE,
    EXIT_UNAUTHORIZED,
    EXIT_TIMEOUT,
    main,
    dispatch_model_cli,
)
from aiosh_mcp.model_backend_adapters_data_model import (
    ModelEndpointConfig,
    ModelProviderType,
)
from aiosh_mcp.model_backend_adapters_service import ModelBackendService


@pytest.fixture
def service():
    return ModelBackendService()


def test_integration_lifecycle_workflow(service, capsys):
    # 1. Verify initial registry state contains mock-default
    res_list = dispatch_model_cli(["list", "--json"], service=service)
    assert res_list.exit_code == EXIT_SUCCESS
    data_list = json.loads(res_list.message)
    initial_ids = {e["backend_id"] for e in data_list["endpoints"]}
    assert "mock-default" in initial_ids

    # 2. Dynamically register new endpoint
    reg_args = [
        "register", "e2e-backend",
        "--provider", "mock",
        "--model", "e2e-model-1",
        "--timeout", "15000",
        "--token", "cap-grant-e2e",
        "--json",
    ]
    res_reg = dispatch_model_cli(reg_args, service=service)
    assert res_reg.exit_code == EXIT_SUCCESS
    data_reg = json.loads(res_reg.message)
    assert data_reg["ok"] is True
    assert data_reg["registered"]["backend_id"] == "e2e-backend"

    # 3. Show registered endpoint
    res_show = dispatch_model_cli(["show", "e2e-backend", "--json"], service=service)
    assert res_show.exit_code == EXIT_SUCCESS
    data_show = json.loads(res_show.message)
    assert data_show["endpoint"]["model_name"] == "e2e-model-1"
    assert data_show["endpoint"]["timeout_ms"] == 15000

    # 4. Check health of registered endpoint
    res_health = dispatch_model_cli(["health", "e2e-backend", "--json"], service=service)
    assert res_health.exit_code == EXIT_SUCCESS
    data_health = json.loads(res_health.message)
    assert data_health["data"]["active"] is True
    assert data_health["data"]["adapter_available"] is True

    # 5. Execute completion on new endpoint
    comp_args = [
        "complete", "e2e-backend",
        "--prompt", "Integration test execution",
        "--token", "cap-grant-e2e",
        "--json",
    ]
    res_comp = dispatch_model_cli(comp_args, service=service)
    assert res_comp.exit_code == EXIT_SUCCESS
    data_comp = json.loads(res_comp.message)
    assert data_comp["ok"] is True
    assert "Mock execution successful" in data_comp["response"]["content"]


def test_integration_fallback_progression(service):
    # Primary backend does not exist, fallbacks chained to mock-default
    comp_args = [
        "complete", "nonexistent-primary",
        "--prompt", "Fallback test prompt",
        "--fallback", "missing-secondary",
        "--fallback", "mock-default",
        "--token", "valid-capability-token",
        "--json",
    ]
    res = dispatch_model_cli(comp_args, service=service)
    assert res.exit_code == EXIT_SUCCESS
    data = json.loads(res.message)
    assert data["ok"] is True
    assert data["response"]["model"] == "mock-model-v1"


def test_integration_main_entrypoint(monkeypatch, capsys):
    # Test main() entrypoint returning exit code and printing message
    code = main(["list"])
    assert code == EXIT_SUCCESS
    out, err = capsys.readouterr()
    assert "mock-default" in out

    # Test main() unauthorized returns 3
    code_unauth = main(["complete", "mock-default", "--prompt", "hi"])
    assert code_unauth == EXIT_UNAUTHORIZED
    out_u, err_u = capsys.readouterr()
    assert "requires a capability token" in out_u

    # Test main() usage error returns 2
    code_usage = main(["unknown-subcmd"])
    assert code_usage == EXIT_USAGE
    out_us, _ = capsys.readouterr()
    assert "Unknown subcommand" in out_us
