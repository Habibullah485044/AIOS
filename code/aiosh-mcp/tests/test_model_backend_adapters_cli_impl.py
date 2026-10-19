"""Implementation tests for Model Backend Adapters CLI surface (T-03186)."""

import json
import pytest

from aiosh_mcp.model_backend_adapters_cli import (
    EXIT_SUCCESS,
    EXIT_FAILURE,
    EXIT_USAGE,
    EXIT_UNAUTHORIZED,
    EXIT_TIMEOUT,
    ModelCliOutput,
    parse_model_cli_args,
    dispatch_model_cli,
)
from aiosh_mcp.model_backend_adapters_data_model import (
    ModelEndpointConfig,
    ModelProviderType,
)
from aiosh_mcp.model_backend_adapters_service import (
    ModelBackendService,
    ModelServiceError,
    MODSERV_ERR_TIMEOUT,
)


@pytest.fixture
def service():
    return ModelBackendService()


def test_cli_list_plain_and_json(service):
    # Plain text list
    res_plain = dispatch_model_cli(["list"], service=service)
    assert res_plain.exit_code == EXIT_SUCCESS
    assert "mock-default" in res_plain.message

    # JSON list
    res_json = dispatch_model_cli(["list", "--json"], service=service)
    assert res_json.exit_code == EXIT_SUCCESS
    data = json.loads(res_json.message)
    assert data["ok"] is True
    assert data["status"] == "success"
    assert data["count"] > 0
    ids = [e["backend_id"] for e in data["endpoints"]]
    assert "mock-default" in ids

    # Filtered by provider
    res_filt = dispatch_model_cli(["list", "--provider", "mock", "--json"], service=service)
    assert res_filt.exit_code == EXIT_SUCCESS
    data_filt = json.loads(res_filt.message)
    assert len(data_filt["endpoints"]) >= 1
    assert all(e["provider"] == "mock" for e in data_filt["endpoints"])


def test_cli_show_endpoint(service):
    # Success show
    res_show = dispatch_model_cli(["show", "mock-default"], service=service)
    assert res_show.exit_code == EXIT_SUCCESS
    assert "mock-default" in res_show.message

    # Show JSON
    res_show_json = dispatch_model_cli(["show", "mock-default", "--json"], service=service)
    assert res_show_json.exit_code == EXIT_SUCCESS
    payload = json.loads(res_show_json.message)
    assert payload["endpoint"]["backend_id"] == "mock-default"

    # Missing argument
    res_miss = dispatch_model_cli(["show"], service=service)
    assert res_miss.exit_code == EXIT_USAGE

    # Unknown backend
    res_unk = dispatch_model_cli(["show", "nonexistent-id", "--json"], service=service)
    assert res_unk.exit_code == EXIT_FAILURE
    assert "not found" in res_unk.message


def test_cli_health_summary_and_target(service):
    # Overall summary
    res_h = dispatch_model_cli(["health", "--json"], service=service)
    assert res_h.exit_code == EXIT_SUCCESS
    data = json.loads(res_h.message)
    assert "total_endpoints" in data["data"]

    # Target backend
    res_t = dispatch_model_cli(["health", "mock-default"], service=service)
    assert res_t.exit_code == EXIT_SUCCESS
    assert "active=True" in res_t.message

    # Target unknown backend
    res_u = dispatch_model_cli(["health", "unknown-id", "--json"], service=service)
    assert res_u.exit_code == EXIT_FAILURE


def test_cli_complete_and_por_gating(service):
    # Unauthorized without token
    res_no_tok = dispatch_model_cli(
        ["complete", "mock-default", "--prompt", "test prompt"],
        service=service,
    )
    assert res_no_tok.exit_code == EXIT_UNAUTHORIZED

    # Authorized with token
    res_comp = dispatch_model_cli(
        ["complete", "mock-default", "--prompt", "test prompt", "--token", "test-token-grant"],
        service=service,
    )
    assert res_comp.exit_code == EXIT_SUCCESS
    assert "[mock-model-v1]" in res_comp.message

    # JSON complete
    res_comp_json = dispatch_model_cli(
        ["complete", "mock-default", "--prompt", "test prompt", "--token", "test-token-grant", "--json"],
        service=service,
    )
    assert res_comp_json.exit_code == EXIT_SUCCESS
    data = json.loads(res_comp_json.message)
    assert data["ok"] is True
    assert "response" in data


def test_cli_register_endpoint(service):
    # Register without token fails
    res_no_tok = dispatch_model_cli(
        ["register", "custom-model", "--provider", "mock", "--model", "custom-v1"],
        service=service,
    )
    assert res_no_tok.exit_code == EXIT_UNAUTHORIZED

    # Register with token succeeds
    res_reg = dispatch_model_cli(
        ["register", "custom-model", "--provider", "mock", "--model", "custom-v1", "--token", "grant-tok", "--json"],
        service=service,
    )
    assert res_reg.exit_code == EXIT_SUCCESS
    cfg = service.registry.get("custom-model")
    assert cfg.model_name == "custom-v1"

    # Register invalid provider fails
    res_inv = dispatch_model_cli(
        ["register", "custom-bad", "--provider", "nonexistent_prov", "--model", "m", "--token", "grant-tok"],
        service=service,
    )
    assert res_inv.exit_code == EXIT_USAGE


def test_cli_secret_redaction_in_errors(service):
    res = ModelCliOutput.failure(EXIT_FAILURE, "Error with Bearer ghp_abcdef1234567890 key")
    assert "ghp_abcdef1234567890" not in res.message
    assert "[REDACTED_SECRET]" in res.message
