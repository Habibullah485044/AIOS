#!/usr/bin/env python3
"""CLI Smoke & Unit Test for Toolchain Pinning (T-00365)"""

import json
import os
import subprocess
import sys
import tempfile

def _aiosh_bin():
    """Native-separator path to the debug aiosh binary.

    Windows CreateProcess rejects a forward-slash relative path
    (FileNotFoundError WinError 2), so normalize before spawning.
    """
    p = os.path.join("code", "aiosh-rust", "target", "debug",
                     "aiosh.exe" if os.name == "nt" else "aiosh")
    if not os.path.exists(p):
        p = os.path.join("target", "debug",
                         "aiosh.exe" if os.name == "nt" else "aiosh")
    return p


def run_aiosh(*args):
    cmd = [_aiosh_bin(), *args]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return res

def parse_json_output(res):
    output = res.stdout.strip() or res.stderr.strip()
    return json.loads(output)

def test_toolchain_show():
    res = run_aiosh("toolchain", "show")
    if res.returncode != 0:
        print(f"FAIL: aiosh toolchain show returned {res.returncode}")
        print(res.stderr)
        sys.exit(1)
    try:
        data = parse_json_output(res)
        assert data.get("ok") is True, "Expected ok: true"
        assert data.get("subcommand") == "toolchain show"
        manifest_data = data.get("data", {})
        assert "rust_version" in manifest_data
        assert "python_version" in manifest_data
        assert "enforce_hashes" in manifest_data
    except Exception as e:
        print(f"FAIL: invalid JSON or missing fields in show: {e}")
        print("stdout:", res.stdout)
        print("stderr:", res.stderr)
        sys.exit(1)
    print("PASS: aiosh toolchain show")

def test_toolchain_check():
    res = run_aiosh("toolchain", "check")
    if res.returncode != 0:
        print(f"FAIL: aiosh toolchain check returned {res.returncode}")
        print(res.stderr)
        sys.exit(1)
    try:
        data = parse_json_output(res)
        assert data.get("ok") is True, "Expected ok: true"
        assert data.get("subcommand") == "toolchain check"
    except Exception as e:
        print(f"FAIL: invalid JSON or missing fields in check: {e}")
        print("stdout:", res.stdout)
        print("stderr:", res.stderr)
        sys.exit(1)
    print("PASS: aiosh toolchain check")

def test_toolchain_custom_config_valid():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump({
            "rust_version": "1.99.0",
            "python_version": "3.14",
            "node_version": "v24.18",
            "enforce_hashes": False
        }, f)
        temp_path = f.name
    try:
        res = run_aiosh("toolchain", "show", "--config", temp_path)
        assert res.returncode == 0, f"Expected 0, got {res.returncode}"
        data = parse_json_output(res)
        assert data.get("ok") is True
        assert data["data"]["rust_version"]["value"] == "1.99.0"

        res_check = run_aiosh("toolchain", "check", "--config", temp_path)
        assert res_check.returncode == 0, f"Expected 0, got {res_check.returncode}"
        data_check = parse_json_output(res_check)
        assert data_check.get("ok") is True
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
    print("PASS: aiosh toolchain custom config valid")

def test_toolchain_invalid_subcommand():
    res = run_aiosh("toolchain", "invalid_subcmd")
    assert res.returncode != 0, "Expected non-zero exit code for invalid subcommand"
    print("PASS: aiosh toolchain invalid subcommand")

def test_toolchain_missing_config():
    res = run_aiosh("toolchain", "check", "--config", "non_existent_path_12345.json")
    assert res.returncode != 0, "Expected non-zero exit code for missing config"
    try:
        data = parse_json_output(res)
        assert data.get("ok") is False
        assert "error" in data
    except Exception as e:
        print(f"FAIL: expected error envelope in JSON: {e}")
        print("stdout:", res.stdout)
        print("stderr:", res.stderr)
        sys.exit(1)
    print("PASS: aiosh toolchain missing config negative test")

def test_toolchain_corrupted_config():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write("{ invalid json content !!!")
        temp_path = f.name
    try:
        res = run_aiosh("toolchain", "check", "--config", temp_path)
        assert res.returncode != 0, "Expected non-zero exit code for corrupted config"
        data = parse_json_output(res)
        assert data.get("ok") is False
        assert "error" in data
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
    print("PASS: aiosh toolchain corrupted config negative test")

def test_toolchain_mismatch_fails():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump({
            "rust_version": "999.99.99",
            "python_version": "3.14",
            "node_version": None,
            "enforce_hashes": False
        }, f)
        temp_path = f.name
    try:
        res = run_aiosh("toolchain", "check", "--config", temp_path)
        assert res.returncode != 0, "Expected non-zero exit code for version mismatch"
        data = parse_json_output(res)
        assert data.get("ok") is False
        assert "expected rustc 999.99.99" in data.get("error", "")
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
    print("PASS: aiosh toolchain version mismatch negative test")

if __name__ == "__main__":
    if not os.path.exists("code/aiosh-rust/target/debug/aiosh.exe"):
        subprocess.run(["cargo", "build", "--bin", "aiosh"], cwd="code/aiosh-rust", check=True)
    test_toolchain_show()
    test_toolchain_check()
    test_toolchain_custom_config_valid()
    test_toolchain_invalid_subcommand()
    test_toolchain_missing_config()
    test_toolchain_corrupted_config()
    test_toolchain_mismatch_fails()
    print("PASS: test_toolchain_cli_smoke.py")
