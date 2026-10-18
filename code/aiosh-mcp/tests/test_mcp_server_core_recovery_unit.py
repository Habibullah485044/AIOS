"""Focused unit tests for MCP Server Core Recovery & Validation Subsystem (MCPRECV-INV1..MCPRECV-INV5)."""

import json
from pathlib import Path
import pytest
from aiosh_mcp.mcp_server_core_recovery import (
    validate_mcp_store,
    recover_mcp_store,
    validate_store_path,
    McpValidationReport,
    McpValidationIssue,
    MAX_STORE_FILE_BYTES,
    MCPRECV_ERR_INVALID_PATH,
    MCPRECV_ERR_UNAUTHORIZED,
)


def test_mcprecv_inv1_and_inv2_invariants():
    # Valid report
    rep_valid = McpValidationReport(
        store_path="/tmp/store.json",
        is_healthy=True,
        total_records=5,
        valid_records=5,
        invalid_records=0,
        issues=[],
    )
    rep_valid.validate_invariants()

    # Sum violation
    rep_bad_sum = McpValidationReport(
        store_path="/tmp/store.json",
        is_healthy=True,
        total_records=6,
        valid_records=4,
        invalid_records=1,
        issues=[],
    )
    with pytest.raises(AssertionError) as exc_info:
        rep_bad_sum.validate_invariants()
    assert "MCPRECV-INV1" in str(exc_info.value)

    # Health mismatch violation
    rep_bad_health = McpValidationReport(
        store_path="/tmp/store.json",
        is_healthy=True,
        total_records=2,
        valid_records=1,
        invalid_records=1,
        issues=[McpValidationIssue("ERROR", "CODE", "msg", "/tmp/store.json")],
    )
    with pytest.raises(AssertionError) as exc_info:
        rep_bad_health.validate_invariants()
    assert "MCPRECV-INV2" in str(exc_info.value)


def test_mcprecv_inv3_quarantine_backup_integrity(tmp_path: Path):
    store_file = tmp_path / "target_store.json"
    corrupt_content = '{"unclosed": "brace", "num": 123'
    store_file.write_text(corrupt_content, encoding="utf-8")

    res = recover_mcp_store(str(store_file), capability_token="token:valid-token-123")
    assert res.ok is True
    assert res.action_taken == "QUARANTINE_AND_RESET"
    assert res.backup_path is not None

    backup_file = Path(res.backup_path)
    assert backup_file.exists()
    assert backup_file.name.startswith("target_store.json.bak.")
    assert backup_file.read_text(encoding="utf-8") == corrupt_content


def test_mcprecv_inv4_path_traversal_and_bounds():
    with pytest.raises(ValueError) as exc_info:
        validate_store_path("../escape/store.json")
    assert MCPRECV_ERR_INVALID_PATH in str(exc_info.value)

    with pytest.raises(ValueError) as exc_info:
        validate_store_path("store\0null.json")
    assert MCPRECV_ERR_INVALID_PATH in str(exc_info.value)

    with pytest.raises(ValueError) as exc_info:
        validate_store_path("a" * 1025)
    assert MCPRECV_ERR_INVALID_PATH in str(exc_info.value)


def test_mcprecv_inv5_por_invariant_i2_token_gating(tmp_path: Path):
    store_file = tmp_path / "broken.json"
    store_file.write_text("invalid", encoding="utf-8")

    # Empty token fails closed
    with pytest.raises(PermissionError) as exc_info:
        recover_mcp_store(str(store_file), capability_token="")
    assert MCPRECV_ERR_UNAUTHORIZED in str(exc_info.value)

    # Whitespace token fails closed
    with pytest.raises(PermissionError) as exc_info:
        recover_mcp_store(str(store_file), capability_token="   \t")
    assert MCPRECV_ERR_UNAUTHORIZED in str(exc_info.value)


def test_file_size_bounds_exceeded(tmp_path: Path):
    store_file = tmp_path / "oversized.json"
    # Create file larger than MAX_STORE_FILE_BYTES (10 MiB)
    with open(store_file, "wb") as f:
        f.seek(MAX_STORE_FILE_BYTES + 1024)
        f.write(b"0")

    report = validate_mcp_store(str(store_file))
    report.validate_invariants()
    assert report.is_healthy is False
    assert any(i.code == "BOUNDS_EXCEEDED" for i in report.issues)
