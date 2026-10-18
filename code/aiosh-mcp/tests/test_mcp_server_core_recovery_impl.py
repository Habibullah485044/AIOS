"""Implementation tests for MCP Server Core Recovery & Validation (T-03156)."""

import json
import pytest
from pathlib import Path
from aiosh_mcp.mcp_server_core_recovery import (
    validate_mcp_store,
    recover_mcp_store,
    MCPRECV_ERR_UNAUTHORIZED,
)


def test_validate_healthy_store(tmp_path: Path):
    store_file = tmp_path / "valid_store.json"
    data = {"version": "1.0", "sessions": {"sess-1": {"user": "kali"}}}
    store_file.write_text(json.dumps(data), encoding="utf-8")

    report = validate_mcp_store(str(store_file))
    report.validate_invariants()
    assert report.is_healthy is True
    assert report.total_records == 2
    assert report.valid_records == 2
    assert report.invalid_records == 0
    assert len(report.issues) == 0


def test_validate_corrupt_store(tmp_path: Path):
    store_file = tmp_path / "corrupt_store.json"
    store_file.write_text('{"unclosed_json": true,', encoding="utf-8")

    report = validate_mcp_store(str(store_file))
    report.validate_invariants()
    assert report.is_healthy is False
    assert report.total_records == 1
    assert report.valid_records == 0
    assert report.invalid_records == 1
    assert any(i.code == "INVALID_JSON" for i in report.issues)


def test_recover_corrupt_store_with_token(tmp_path: Path):
    store_file = tmp_path / "broken_store.json"
    corrupt_content = '{"broken": [1, 2, 3,'
    store_file.write_text(corrupt_content, encoding="utf-8")

    # Recovery with valid capability token
    token = "token:admin-grant-12345"
    result = recover_mcp_store(str(store_file), capability_token=token)

    assert result.ok is True
    assert result.action_taken == "QUARANTINE_AND_RESET"
    assert result.backup_path is not None
    assert Path(result.backup_path).exists()
    assert Path(result.backup_path).read_text(encoding="utf-8") == corrupt_content

    # The store file should now be a healthy default JSON
    assert store_file.exists()
    recovered_data = json.loads(store_file.read_text(encoding="utf-8"))
    assert recovered_data.get("metadata", {}).get("recovered") is True
    assert result.report.is_healthy is True


def test_recover_unauthorized_token_rejection(tmp_path: Path):
    store_file = tmp_path / "store.json"
    store_file.write_text("invalid json", encoding="utf-8")

    # Missing/empty token must be rejected fail-closed under PoR Invariant I-2
    with pytest.raises(PermissionError) as exc_info:
        recover_mcp_store(str(store_file), capability_token="")
    assert MCPRECV_ERR_UNAUTHORIZED in str(exc_info.value)

    with pytest.raises(PermissionError) as exc_info:
        recover_mcp_store(str(store_file), capability_token="   ")
    assert MCPRECV_ERR_UNAUTHORIZED in str(exc_info.value)
