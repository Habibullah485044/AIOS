#!/usr/bin/env python3
"""Compliance Mapping MCP/API Surface — Integration Test Suite (T-02898).

Verifies the feature end-to-end through its production surfaces:

  1. Discoverability — the real MCP server (`python -m aiosh_mcp.server` over
     stdio) advertises `aios_compliance` in tools/list with its schema.
  2. E2E tool calls over the wire — read actions succeed with audit rows;
     domain errors propagate as spec §4 envelopes.
  3. Gated write over the wire — an ungranted register is refused at the PEP
     gate (fail-closed: no store file, exactly one refusal audit row); the
     same call with a pre-minted scope grant succeeds and persists the store.
  4. Cross-substrate parity — the Rust CLI (`aiosh compliance ... --path`)
     and the Python surface operate on ONE shared canonical-JSON store:
     init baseline, id listing, show, status transition and assess all agree,
     and each substrate loads the other's store bytes (regression guard for
     the serde/as_str framework-name split fixed in T-02898).

Contract: docs/tasks/evidence/T-02894-spec.md (normative).
Run: python3 -m pytest code/aiosh-mcp/tests/test_compliance_integration.py -q
"""

from __future__ import annotations

import json
import os
import queue
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]   # repo root
PKG_PARENT = Path(__file__).resolve().parents[1]  # code/aiosh-mcp (package dir)
for _p in (str(ROOT), str(PKG_PARENT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from aiosh_mcp import audit_client, compliance  # noqa: E402

SERVER_DIR = ROOT / "code" / "aiosh-mcp"
RUST_BIN_CANDIDATES = (
    ROOT / "code" / "aiosh-rust" / "target" / "debug" / "aiosh.exe",
    ROOT / "code" / "aiosh-rust" / "target" / "debug" / "aiosh",
)


def _rust_bin() -> Path | None:
    for cand in RUST_BIN_CANDIDATES:
        if cand.exists():
            return cand.resolve()
    return None


def rust(*args: str) -> subprocess.CompletedProcess:
    bin_ = _rust_bin()
    assert bin_ is not None, "Rust aiosh binary missing"
    return subprocess.run([str(bin_), "compliance", *args],
                          capture_output=True, text=True, timeout=30)


# ---------------------------------------------------------------------------
# Wire harness (raw JSON-RPC over stdio against the production server)
# ---------------------------------------------------------------------------

@contextmanager
def wire_env():
    """Isolated AIOSH_HOME + compliance store for one subprocess session."""
    with tempfile.TemporaryDirectory(prefix="compliance-int-") as td:
        home = Path(td) / ".aios"
        home.mkdir(parents=True, exist_ok=True)
        store = Path(td) / "compliance_map.json"
        old_home = os.environ.get("AIOSH_HOME")
        old_store = os.environ.get("AIOSH_COMPLIANCE_MAP_PATH")
        os.environ["AIOSH_HOME"] = str(home)
        os.environ["AIOSH_COMPLIANCE_MAP_PATH"] = str(store)
        try:
            yield {"home": home, "store": store}
        finally:
            for key, old in (("AIOSH_HOME", old_home),
                             ("AIOSH_COMPLIANCE_MAP_PATH", old_store)):
                if old is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = old


def wire(requests: list[dict], timeout: float = 60.0) -> dict[int, dict]:
    """Run the production MCP server once; return id -> JSON-RPC response.

    stdin is kept OPEN until every response arrives: FastMCP begins shutting
    down as soon as it sees stdin EOF, which races with — and drops — the
    response of the last tools/call in the batch (observed T-02898).
    """
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    proc = subprocess.Popen(
        [sys.executable, "-m", "aiosh_mcp.server"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, encoding="utf-8", bufsize=1,
        cwd=str(SERVER_DIR), env=env,
    )

    def _write() -> None:
        for r in requests:
            proc.stdin.write(json.dumps(r) + "\n")
        proc.stdin.flush()

    responses: queue.Queue[dict] = queue.Queue()

    def _read() -> None:
        for line in proc.stdout:
            if line.strip():
                try:
                    responses.put(json.loads(line))
                except json.JSONDecodeError:
                    pass

    threading.Thread(target=_write, daemon=True).start()
    threading.Thread(target=_read, daemon=True).start()

    out: dict[int, dict] = {}
    deadline = time.time() + timeout
    while len(out) < len(requests) and time.time() < deadline:
        try:
            d = responses.get(timeout=0.5)
            out[d.get("id")] = d
        except queue.Empty:
            if proc.poll() is not None:
                break
    try:
        proc.stdin.close()
    except OSError:
        pass
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10)
    stderr_tail = proc.stderr.read()[:400] if proc.stderr else ""
    assert len(out) == len(requests), (
        f"server returned {sorted(out)} for sent "
        f"{[r.get('id') for r in requests]} (rc={proc.returncode}): {stderr_tail}")
    assert proc.returncode == 0, f"server exited {proc.returncode}: {stderr_tail}"
    return out


def init_req(i: int = 1) -> dict:
    return {"jsonrpc": "2.0", "id": i, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "compliance-int", "version": "1"}}}


def list_req(i: int = 2) -> dict:
    return {"jsonrpc": "2.0", "id": i, "method": "tools/list", "params": {}}


def call_req(i: int, name: str, arguments: dict) -> dict:
    return {"jsonrpc": "2.0", "id": i, "method": "tools/call",
            "params": {"name": name, "arguments": arguments}}


def wire_result(resp: dict) -> dict:
    return json.loads(resp["result"]["content"][0]["text"])


def mint_grant(tools: list[str], grant_id: str = "gr_int_test_001") -> str:
    conn = audit_client.open_db()
    try:
        audit_client.ensure_pep_schema(conn)
        scope = {"tools": tools, "paths": [], "networks": []}
        scope_json = json.dumps(scope, sort_keys=True)
        conn.execute(
            """INSERT INTO pep_grants (grant_id, issued_at, expires_at,
               issued_to, constitution_rev, scope_json, scope_hash, single_use)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (grant_id, "2026-10-01T00:00:00Z", "2199-12-31T23:59:59Z",
             "agent:test", "rev-test", scope_json,
             audit_client.sha256_hex(scope_json), 0))
        conn.commit()
    finally:
        conn.close()
    return grant_id


def audit_count() -> int:
    conn = audit_client.open_db()
    try:
        return conn.execute("SELECT COUNT(*) c FROM audit_ring").fetchone()["c"]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 1. Discoverability through the production surface
# ---------------------------------------------------------------------------

def test_mcp_stdio_advertises_compliance_tool():
    with wire_env():
        out = wire([init_req(1), list_req(2)])
        assert out[1]["result"]["serverInfo"]["name"] == "aiosh-mcp"
        tools = out[2]["result"]["tools"]
        names = [t["name"] for t in tools]
        assert "aios_compliance" in names, f"not discoverable: {names}"
        schema = next(t for t in tools if t["name"] == "aios_compliance")
        props = schema["inputSchema"]["properties"]
        for required_prop in ("action", "id", "grant_id", "gate_id"):
            assert required_prop in props, f"schema missing {required_prop}"


# ---------------------------------------------------------------------------
# 2. E2E tool calls over the wire
# ---------------------------------------------------------------------------

def test_mcp_stdio_read_calls_end_to_end():
    with wire_env() as env:
        out = wire([
            init_req(1),
            call_req(2, "aios_compliance", {"action": "assess"}),
            call_req(3, "aios_compliance", {"action": "show", "id": "MAP-NOPE"}),
        ])

        ok = wire_result(out[2])
        assert out[2]["result"]["isError"] is False
        assert ok["ok"] is True and ok["action"] == "assess"
        assert ok["report"]["total_mappings"] == 4        # canonical baseline
        assert ok["report"]["compliance_percentage"] == 100.0
        assert ok["audit_id"] > 0

        neg = wire_result(out[3])
        assert neg["ok"] is False and neg["action"] == "show"
        assert "COMPLIANCESVC_ERR_NOT_FOUND" in neg["error"]
        assert neg["audit_id"] > 0

        # exactly one audit row per call (spec §7)
        assert audit_count() == 2
        # reads never create the store file (spec §5)
        assert not env["store"].exists()


# ---------------------------------------------------------------------------
# 3. Gated write over the wire: fail-closed, then grant-succeeds
# ---------------------------------------------------------------------------

def test_wire_ungranted_write_refused_fail_closed():
    with wire_env() as env:
        n0 = audit_count()
        out = wire([
            init_req(1),
            call_req(2, "aios_compliance", {
                "action": "register", "id": "MAP-WIRE-001",
                "control_id": "AC-1", "framework": "nist",
                "target_type": "pep_gate", "target_ref": "gate.wire",
                "status": "non_compliant"}),
        ])
        r = wire_result(out[2])
        assert r["ok"] is False
        assert r["gate"] == "pep"
        assert "requires explicit PEP grant" in r["reason"]
        assert not env["store"].exists()          # fail-closed: nothing written
        assert audit_count() == n0 + 1            # exactly one refusal row


def test_wire_granted_write_persists_store():
    with wire_env() as env:
        grant_id = mint_grant(["aios.compliance"])
        n0 = audit_count()
        out = wire([
            init_req(1),
            call_req(2, "aios_compliance", {
                "action": "register", "id": "MAP-WIRE-002",
                "control_id": "AC-2", "framework": "nist",
                "target_type": "pep_gate", "target_ref": "gate.wire2",
                "status": "non_compliant", "grant_id": grant_id}),
        ])
        r = wire_result(out[2])
        assert r["ok"] is True and r["action"] == "register"
        assert r["mapping"]["id"] == "MAP-WIRE-002"
        assert r["audit_id"] > 0

        obj = json.loads(env["store"].read_text(encoding="utf-8"))
        ids = [m["id"] for m in obj["mappings"]]
        assert "MAP-WIRE-002" in ids and len(ids) == 5  # baseline 4 + new
        # invariant I-2: redemption row + result row for the granted call
        assert audit_count() == n0 + 2


# ---------------------------------------------------------------------------
# 4. Cross-substrate parity on the shared canonical-JSON store
# ---------------------------------------------------------------------------

def test_cross_substrate_init_baseline_and_loads():
    """Rust-init and Python-init stores are mutually readable and agree on
    the canonical baseline (regression guard: framework enum serde names)."""
    if _rust_bin() is None:
        pytest.skip("aiosh Rust binary not built")

    with tempfile.TemporaryDirectory(prefix="compliance-xsub-") as td:
        rust_store = os.path.join(td, "rust_init.json")
        p = rust("init", "--path", rust_store)
        assert p.returncode == 0, p.stderr or p.stdout

        # Rust baseline must use the canonical framework strings that Python
        # (and parse_framework/as_str) accept — previously failed with
        # `unknown variant nist_sp_800_53_rev5`.
        obj = json.loads(Path(rust_store).read_text(encoding="utf-8"))
        fw = [m["framework"] for m in obj["mappings"]]
        assert all(f in compliance.FRAMEWORKS for f in fw), fw

        # Python reads Rust's store and sees the same ids in the same order
        os.environ["AIOSH_COMPLIANCE_MAP_PATH"] = rust_store
        try:
            py_ids = [m["id"] for m in compliance.execute(action="list")["mappings"]]
        finally:
            os.environ.pop("AIOSH_COMPLIANCE_MAP_PATH", None)
        p = rust("list", "--json", "--path", rust_store)
        assert p.returncode == 0, p.stdout
        rust_ids = [m["id"] for m in json.loads(p.stdout)["mappings"]]
        assert py_ids == rust_ids

        # Python-init store must be loadable by Rust (previously rc=3 PARSE)
        py_store = os.path.join(td, "py_init.json")
        compliance.init_store(py_store)
        p = rust("list", "--json", "--path", py_store)
        assert p.returncode == 0, p.stdout
        assert json.loads(p.stdout)["count"] == 4

        # Byte-level canonical form: Python load->save over Rust-written bytes
        # is a no-op (identical serializer on both substrates, spec §5).
        before = Path(rust_store).read_bytes()
        snap = compliance.load_store(rust_store)
        compliance.save_store(rust_store, snap)
        assert Path(rust_store).read_bytes() == before


def test_cross_substrate_register_show_status_assess():
    if _rust_bin() is None:
        pytest.skip("aiosh Rust binary not built")

    with tempfile.TemporaryDirectory(prefix="compliance-xsub2-") as td:
        store = os.path.join(td, "shared.json")
        assert rust("init", "--path", store).returncode == 0

        # Python writes -> Rust reads
        os.environ["AIOSH_COMPLIANCE_MAP_PATH"] = store
        try:
            res = compliance.execute(action="register", id="MAP-XINT-001",
                                     control_id="AC-7", framework="soc2",
                                     target_type="pep_gate", target_ref="gate.x",
                                     status="non_compliant")
            assert res["ok"] is True

            p = rust("show", "MAP-XINT-001", "--json", "--path", store)
            assert p.returncode == 0, p.stdout
            shown = json.loads(p.stdout)["mapping"]
            assert shown["framework"] == "soc2_type2"
            assert shown["status"] == "non_compliant"
            assert shown["target_ref"] == "gate.x"

            # Rust transitions status -> Python observes it
            p = rust("status", "MAP-XINT-001", "compliant",
                     "--reason", "parity", "--path", store)
            assert p.returncode == 0, p.stdout
            back = compliance.execute(action="show", id="MAP-XINT-001")
            assert back["mapping"]["status"] == "compliant"

            # assess parity on the shared store, scoped to one framework
            py_rep = compliance.execute(action="assess", framework="soc2")["report"]
            p = rust("assess", "--framework", "soc2", "--json", "--path", store)
            assert p.returncode == 0, p.stdout
            rs_rep = json.loads(p.stdout)["assessment"]
            assert py_rep["total_mappings"] == rs_rep["total_mappings"] == 2
            assert py_rep["compliant_count"] == rs_rep["compliant_count"] == 2
            assert py_rep["compliance_percentage"] == rs_rep["compliance_percentage"]
        finally:
            os.environ.pop("AIOSH_COMPLIANCE_MAP_PATH", None)
