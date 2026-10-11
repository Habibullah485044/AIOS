"""Integration tests for Compliance Mapping Recovery and Validation (T-02958)."""

import json
from pathlib import Path
import pytest

from aiosh_mcp.compliance import (
    canonical_baseline,
    save_store,
    execute,
)
from aiosh_mcp.compliance_recovery import (
    ComplianceCatalogStatus,
)


def test_compliance_mcp_recovery_integration_e2e(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    store_file = tmp_path / "compliance_map.json"
    monkeypatch.setenv("AIOSH_COMPLIANCE_MAP_PATH", str(store_file))

    base = canonical_baseline()
    save_store(str(store_file), base)

    # 1. MCP action: recovery-verify
    verify_res = execute(action="recovery-verify")
    assert verify_res["ok"]
    report = verify_res["report"]
    assert report["status"] == "healthy"
    assert report["valid_mappings"] == 4
    assert report["corrupted_mappings"] == 0
    assert not report["has_backup"]

    # 2. MCP action: recovery-backup
    backup_res = execute(action="recovery-backup")
    assert backup_res["ok"]
    backup_path = Path(backup_res["backup_path"])
    assert backup_path.exists()

    # 3. Corrupt active store
    store_file.write_text("CORRUPTED_NON_JSON", encoding="utf-8")

    corrupt_verify = execute(action="recovery-verify")
    assert corrupt_verify["ok"]
    assert corrupt_verify["report"]["status"] == "corrupted"

    # 4. MCP action: recovery-restore
    restore_res = execute(action="recovery-restore")
    assert restore_res["ok"]
    assert restore_res["report"]["mappings_recovered"] == 4

    # 5. Verify restored catalog
    post_restore = execute(action="recovery-verify")
    assert post_restore["ok"]
    assert post_restore["report"]["status"] == "healthy"
    assert post_restore["report"]["valid_mappings"] == 4

    # 6. MCP action: recovery-repair on degraded store
    data = json.loads(store_file.read_text(encoding="utf-8"))
    data["mappings"].append({
        "id": "MAP-BROKEN",
        "control_id": "",
        "target_ref": "",
    })
    store_file.write_text(json.dumps(data), encoding="utf-8")

    repair_res = execute(action="recovery-repair")
    assert repair_res["ok"]
    assert repair_res["report"]["mappings_recovered"] == 4
    assert repair_res["report"]["mappings_dropped"] == 1
    assert repair_res["report"]["quarantined_path"] is not None
    assert Path(repair_res["report"]["quarantined_path"]).exists()
