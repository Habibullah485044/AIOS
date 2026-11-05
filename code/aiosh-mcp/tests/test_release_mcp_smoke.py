"""T-245: Unit tests for MCP/API surface of Release Packaging & Backup."""
import pytest
from aiosh_mcp.release import (
    PackageManifest, BackupSnapshot,
    generate_release, create_backup,
    register_release_tools, _cls_kwargs,
)


def test_cls_kwargs_extraction():
    """Test that _cls_kwargs correctly extracts classifier fields."""
    verdict = {
        "ok": True,
        "policy_revision": "rev-1",
        "classify_rule_ids": ["r1"],
        "classify_evidence": {"c1": []},
        "classify_overall_verdict": "ok",
        "classify_verdict_reason": "",
    }
    kw = _cls_kwargs(verdict)
    assert kw["policy_revision"] == "rev-1"
    assert kw["classify_rule_ids"] == ["r1"]
    assert kw["classify_overall_verdict"] == "ok"


def test_cls_kwargs_missing_fields():
    """Negative: _cls_kwargs handles missing keys gracefully."""
    verdict = {"ok": True}
    kw = _cls_kwargs(verdict)
    assert kw["policy_revision"] is None
    assert kw["classify_rule_ids"] is None


def test_generate_release_returns_tuple():
    """Happy path: generate_release returns (path, hash)."""
    m = PackageManifest(target_os="test", components=["core"], version="0.1.0")
    path, h = generate_release(m, "test-actor", "v0.0")
    assert path == "output/release/aios_test_0.1.0.iso"
    assert isinstance(h, str) and len(h) == 64


def test_create_backup_returns_path(tmp_path, monkeypatch):
    """Happy path: create_backup returns a zip filename (run in a temp dir: the zip is written to the CWD)."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AIOSH_HOME", str(tmp_path / "home"))
    s = BackupSnapshot(target_path=".", include_audit=True, include_memory=False)
    p = create_backup(s, "test-actor", "v0.0")
    assert p.startswith("aios_backup_")
    assert p.endswith(".zip")


def test_generate_release_boundary_empty_components():
    """Boundary: empty components list."""
    m = PackageManifest(target_os="x", components=[], version="0.0.1")
    path, h = generate_release(m, "test-actor", "v0.0")
    assert "aios_x_0.0.1.iso" in path


def test_register_release_tools_callable():
    """Verify register_release_tools is callable with correct signature."""
    assert callable(register_release_tools)
