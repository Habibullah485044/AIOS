"""Regression: a backup must never archive itself or earlier backups (fix 2026-11-06).

`release.create_backup` writes `aios_backup_<ts>.zip` into the CWD. With `target_path="."` the walk
reached the archive being written, which then grew by including itself until the disk was full (10.9 GB).
"""

import os
import zipfile

from aiosh_mcp.release import BackupSnapshot, create_backup


def test_backup_of_cwd_does_not_include_itself(tmp_path, monkeypatch):
    work = tmp_path / "work"
    work.mkdir()
    (work / "data.txt").write_text("payload " * 1000, encoding="utf-8")
    (work / "aios_backup_2020-01-01T00-00-00-000000Z.zip").write_bytes(b"old backup" * 1000)   # an earlier backup
    monkeypatch.chdir(work)
    monkeypatch.setenv("AIOSH_HOME", str(tmp_path / "home"))
    path = create_backup(BackupSnapshot(target_path=".", include_audit=False, include_memory=False), "t", "v0")
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
    assert names == ["data.txt"]
    assert os.path.getsize(path) < 64 * 1024                     # bounded: payload only, no nesting
