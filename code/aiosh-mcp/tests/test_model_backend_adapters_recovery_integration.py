"""Integration tests for Model Backend Adapters Recovery & Validation Subsystem (T-03258)."""

import json
from pathlib import Path
import pytest
from aiosh_mcp.server import mcp
from aiosh_mcp.model_backend_adapters_recovery import (
    MODRECV_ERR_UNAUTHORIZED,
    MODRECV_ERR_CORRUPT_JSON,
)


@pytest.mark.anyio
async def test_integration_mcp_recovery_tools_registration():
    tools = await mcp.list_tools()
    tool_names = [t.name for t in tools]
    assert "aios_model_validate_config" in tool_names
    assert "aios_model_recover_config" in tool_names


@pytest.mark.anyio
async def test_integration_mcp_validate_config_valid(tmp_path: Path):
    cfg_file = tmp_path / "valid_models.json"
    cfg_data = {
        "models": [
            {
                "name": "integration-mock",
                "provider": "mock",
                "endpoint_url": "http://localhost:8080/mock",
                "max_tokens": 2048,
            }
        ]
    }
    cfg_file.write_text(json.dumps(cfg_data), encoding="utf-8")

    result = await mcp.call_tool(
        "aios_model_validate_config", {"config_path": str(cfg_file)}
    )
    assert result is not None
    text = result[0].text
    assert '"status": "success"' in text or '"ok": true' in text.lower()
    assert '"is_healthy": true' in text.lower()


@pytest.mark.anyio
async def test_integration_mcp_validate_config_corrupt(tmp_path: Path):
    cfg_file = tmp_path / "corrupt_models.json"
    cfg_file.write_text("{ corrupt json data ...", encoding="utf-8")

    result = await mcp.call_tool(
        "aios_model_validate_config", {"config_path": str(cfg_file)}
    )
    assert result is not None
    text = result[0].text
    assert '"is_healthy": false' in text.lower()
    assert MODRECV_ERR_CORRUPT_JSON in text


@pytest.mark.anyio
async def test_integration_mcp_recover_config_unauthorized(tmp_path: Path):
    cfg_file = tmp_path / "unauthorized_target.json"
    result = await mcp.call_tool(
        "aios_model_recover_config",
        {"config_path": str(cfg_file), "capability_token": ""},
    )
    assert result is not None
    text = result[0].text
    assert MODRECV_ERR_UNAUTHORIZED in text


@pytest.mark.anyio
async def test_integration_mcp_recover_config_success(tmp_path: Path):
    cfg_file = tmp_path / "recoverable_models.json"
    cfg_file.write_text("CORRUPTED_INITIAL_STATE", encoding="utf-8")

    result = await mcp.call_tool(
        "aios_model_recover_config",
        {
            "config_path": str(cfg_file),
            "capability_token": "cap_valid_integration_token",
            "create_backup": True,
        },
    )
    assert result is not None
    text = result[0].text
    assert '"status": "success"' in text or '"ok": true' in text.lower()
    assert "QUARANTINE_AND_RESTORE_DEFAULT" in text

    # Validate that restored file is now healthy
    val_result = await mcp.call_tool(
        "aios_model_validate_config", {"config_path": str(cfg_file)}
    )
    val_text = val_result[0].text
    assert '"is_healthy": true' in val_text.lower()
