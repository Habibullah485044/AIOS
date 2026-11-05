import pytest
import os
import shutil
from aiosh_mcp.release import PackageManifest, BackupSnapshot, generate_release, create_backup
from aiosh_mcp import audit_client

TMP_HOME = "/tmp/aios_test_release_smoke"

@pytest.fixture(autouse=True)
def memory_db(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)          # create_backup writes its zip to the CWD; keep it out of the repo
    monkeypatch.setenv("AIOSH_HOME", TMP_HOME)
    if os.path.exists(TMP_HOME):
        shutil.rmtree(TMP_HOME, ignore_errors=True)
    yield
    if os.path.exists(TMP_HOME):
        shutil.rmtree(TMP_HOME, ignore_errors=True)

def test_generate_release_valid():
    manifest = PackageManifest(target_os="debian-13", components=["aiosh-mcp", "aiosh-rust"], version="1.0.0")
    path, hash_val = generate_release(manifest, actor_id="user-123", constitution_rev="v1")
    assert path == "output/release/aios_debian-13_1.0.0.iso"
    assert len(hash_val) == 64
    
    with audit_client.open_db() as conn:
        rows = audit_client.tail(conn, 1)
        assert len(rows) == 1
        assert rows[0].tool == "aios.release.generate"
        assert rows[0].actor_id == "user-123"
        assert rows[0].args["target_os"] == "debian-13"
        assert rows[0].args["components"] == ["aiosh-mcp", "aiosh-rust"]
        assert rows[0].outcome == "success"

def test_generate_release_boundary():
    # Boundary / Negative input tests
    manifest = PackageManifest(target_os="", components=[], version="")
    path, hash_val = generate_release(manifest, actor_id="test", constitution_rev="v1")
    assert len(hash_val) == 64
    assert path == "output/release/aios__.iso"
    
    with audit_client.open_db() as conn:
        rows = audit_client.tail(conn, 1)
        assert rows[0].args["target_os"] == ""
        assert rows[0].args["components"] == []

def test_create_backup_valid():
    snapshot = BackupSnapshot(target_path="/var/aios", include_audit=True, include_memory=False)
    path = create_backup(snapshot, actor_id="user-456", constitution_rev="v2")
    assert path.startswith("aios_backup_")
    assert path.endswith(".zip")
    
    with audit_client.open_db() as conn:
        rows = audit_client.tail(conn, 1)
        assert rows[0].tool == "aios.backup.create"
        assert rows[0].actor_id == "user-456"
        assert rows[0].args["target_path"] == "/var/aios"
        assert rows[0].args["include_audit"] is True
        assert rows[0].args["include_memory"] is False
        assert rows[0].outcome == "success"
