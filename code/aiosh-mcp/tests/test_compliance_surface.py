#!/usr/bin/env python3
"""Compliance Mapping — MCP/API surface Test Suite.

Contract: docs/tasks/evidence/T-02894-spec.md (normative).
T-02895 scaffold (S-* structure); T-02896 implementation (B-* behavior).

  S1..S5  structural: parity constants, vocabularies, action split, field
          order, loud-failure on garbage input
  B1      happy path: register -> list -> show (spec §3 envelope), reads
          never touch the store file
  B2      failure path: spec §4 error-code table
  B3      audit effects: exactly one audit row per call, PEP refusal for
          ungranted writes, grant-gated success (spec §7/§8)
  B4      store persistence: canonical byte-stable form (spec §5)
  B5      validation parity with compliance_data_model.rs (spec §6)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from aiosh_mcp import audit_client, compliance  # noqa: E402


@pytest.fixture
def store(tmp_path, monkeypatch):
    """Isolated compliance store path (never the real docs/compliance_map.json)."""
    p = tmp_path / "compliance_map.json"
    monkeypatch.setenv("AIOSH_COMPLIANCE_MAP_PATH", str(p))
    return p


def _reg(**kw):
    base = dict(action="register", control_id="AC-2", framework="nist",
                target_type="pep_gate", target_ref="pep_enforce_gate",
                status="compliant", mitigation_summary="PEP enforced")
    base.update(kw)
    return compliance.execute(**base)


# ---------------------------------------------------------------------------
# S-* — structure / parity (green since T-02895)
# ---------------------------------------------------------------------------

def test_s1_constants_match_rust_parity():
    """Spec §6 binding parity with compliance_data_model.rs."""
    assert compliance.MAX_COMPLIANCE_ID_LEN == 64
    assert compliance.MAX_COMPLIANCE_TITLE_LEN == 128
    assert compliance.MAX_COMPLIANCE_DESC_LEN == 2048
    assert compliance.MAX_COMPLIANCE_NOTES_LEN == 2048
    assert compliance.MAX_THREAT_IDS_COUNT == 16
    assert compliance.MAX_TAGS_COUNT == 16
    assert compliance.MAX_COMPLIANCE_ENTRIES_CAPACITY == 1024


def test_s2_closed_vocabularies():
    assert set(compliance.FRAMEWORKS) == {
        "nist_sp_800_53_rev5", "soc2_type2", "iso_27001_2022",
        "cis_controls_v8", "hipaa_security", "pci_dss_v4"}
    assert set(compliance.STATUSES) == {
        "compliant", "partially_compliant", "non_compliant", "not_applicable"}
    assert set(compliance.TARGET_TYPES) == {
        "pep_gate", "capability_token", "audit_ring", "threat_mitigation",
        "constitution_rule"}
    assert set(compliance.FRAMEWORK_ALIASES.values()) <= set(compliance.FRAMEWORKS)
    assert set(compliance.STATUS_ALIASES.values()) <= set(compliance.STATUSES)


def test_s3_action_vocabulary_and_gating_split():
    """Spec §2/§8: seven verbs + stats + doc actions; exactly three are write actions."""
    assert set(compliance.ACTIONS) == {
        "list", "show", "register", "status", "assess", "check-pep", "init",
        "stats", "doc-list", "doc-get", "doc-search"}
    assert set(compliance.WRITE_ACTIONS) == {"register", "status", "init"}
    assert set(compliance.READ_ACTIONS) == {
        "list", "show", "assess", "check-pep", "stats", "doc-list", "doc-get", "doc-search"}
    assert not set(compliance.READ_ACTIONS) & set(compliance.WRITE_ACTIONS)


def test_s4_entry_field_order_matches_rust():
    """Byte-stable round-trip (spec §5) requires the Rust struct order."""
    assert [f for f in compliance.ComplianceMappingEntry.__dataclass_fields__] == [
        "id", "control_id", "framework", "target_type", "target_ref",
        "threat_ids", "status", "mitigation_summary", "tags",
        "created_at", "updated_at"]
    assert [f for f in compliance.ComplianceCatalogSnapshot.__dataclass_fields__] == [
        "version", "mappings", "generated_at"]


def test_s5_interfaces_fail_loudly_on_garbage(store):
    """Every interface is present; garbage input fails loudly, never silently."""
    for name in ("validate_identifier", "validate_title", "validate_text_length",
                 "parse_framework", "parse_status", "validate_path",
                 "load_store", "save_store", "init_store",
                 "list_mappings", "get_mapping", "build_entry",
                 "register_mapping", "update_status", "assess_framework",
                 "verify_pep_coverage", "uncovered_pep_gates", "execute"):
        assert callable(getattr(compliance, name)), name

    with pytest.raises(ValueError, match="PARAM_INVALID"):
        compliance.execute(action="frobnicate")
    with pytest.raises(ValueError, match="COMPLIANCESVC_ERR_IO"):
        compliance.load_store(str(store))  # missing file -> loud, not baseline


# ---------------------------------------------------------------------------
# B1 — happy path (spec §3)
# ---------------------------------------------------------------------------

def test_b1_happy_path_register_list_show(store):
    res = _reg(id="MAP-TEST-001")
    assert res["ok"] is True and res["action"] == "register"
    m = res["mapping"]
    assert m["id"] == "MAP-TEST-001"
    assert m["framework"] == "nist_sp_800_53_rev5"   # alias canonicalized
    assert m["created_at"] == m["updated_at"] and m["created_at"]
    assert store.exists()

    listed = compliance.execute(action="list")
    # baseline (4) + registered (1)
    assert listed["ok"] and listed["count"] == 5
    assert any(e["id"] == "MAP-TEST-001" for e in listed["mappings"])

    filtered = compliance.execute(action="list", framework="nist")
    assert filtered["count"] == 3   # 2 baseline NIST + the new one
    by_status = compliance.execute(action="list", status="compliant")
    assert all(e["status"] == "compliant" for e in by_status["mappings"])

    shown = compliance.execute(action="show", id="MAP-TEST-001")
    assert shown["ok"] and shown["mapping"]["control_id"] == "AC-2"

    assess = compliance.execute(action="assess")
    rep = assess["report"]
    assert rep["total_mappings"] == 5
    assert (rep["compliant_count"] / rep["total_mappings"]) * 100.0 == pytest.approx(
        rep["compliance_percentage"])

    pep = compliance.execute(action="check-pep", gate_id="pep_enforce_gate")
    assert pep["covered"] is True and pep["uncovered_required"] == []

    # Read actions never touch the store file (spec §5).
    before = (store.stat().st_mtime_ns, store.stat().st_size)
    compliance.execute(action="list")
    compliance.execute(action="assess")
    compliance.execute(action="check-pep", gate_id="x")
    assert (store.stat().st_mtime_ns, store.stat().st_size) == before


def test_b1b_init_creates_baseline_then_refuses(store):
    res = compliance.execute(action="init")
    assert res["ok"] and res["initialized"] is True and res["count"] == 4
    with pytest.raises(ValueError, match="STORE_EXISTS"):
        compliance.execute(action="init")


# ---------------------------------------------------------------------------
# B2 — failure path (spec §4 error-code table)
# ---------------------------------------------------------------------------

def test_b2_failure_codes(store):
    with pytest.raises(ValueError, match="PARAM_INVALID"):
        _reg(id=None)
    with pytest.raises(ValueError, match="COMPLIANCE_ERR_INVALID_ID"):
        _reg(id="bad id with spaces")
    with pytest.raises(ValueError, match="COMPLIANCE_ERR_BOUNDS_EXCEEDED"):
        _reg(id="X" * 65)
    with pytest.raises(ValueError, match="PARAM_INVALID"):
        _reg(id="MAP-X", framework="gdpr")
    with pytest.raises(ValueError, match="PARAM_INVALID"):
        _reg(id="MAP-X", target_type="magic_box")
    with pytest.raises(ValueError, match="COMPLIANCE_ERR_MISSING_SUBSTRATE_REF"):
        _reg(id="MAP-X", target_ref="   ")
    with pytest.raises(ValueError, match="COMPLIANCE_ERR_CONTROL_CHARS"):
        _reg(id="MAP-X", mitigation_summary="ok\x07bad")
    with pytest.raises(ValueError, match="COMPLIANCE_ERR_BOUNDS_EXCEEDED"):
        _reg(id="MAP-X", threat_ids=[f"T-{i}" for i in range(17)])
    with pytest.raises(ValueError, match="COMPLIANCE_ERR_BOUNDS_EXCEEDED"):
        _reg(id="MAP-COMPLIANT-NO-MIT", status="compliant", mitigation_summary="")

    _reg(id="MAP-DUP")
    with pytest.raises(ValueError, match="COMPLIANCE_ERR_DUPLICATE_ID"):
        _reg(id="MAP-DUP")

    with pytest.raises(ValueError, match="PARAM_INVALID"):
        compliance.execute(action="show")            # missing id
    with pytest.raises(ValueError, match="COMPLIANCESVC_ERR_NOT_FOUND"):
        compliance.execute(action="show", id="MAP-NOPE")
    with pytest.raises(ValueError, match="PARAM_INVALID"):
        compliance.execute(action="status", id="MAP-DUP")   # missing status
    with pytest.raises(ValueError, match="COMPLIANCESVC_ERR_NOT_FOUND"):
        compliance.execute(action="status", id="MAP-NOPE",
                           status="compliant")
    with pytest.raises(ValueError, match="PARAM_INVALID"):
        compliance.execute(action="check-pep")        # missing gate_id

    # transition to compliant without mitigation summary nor reason -> BOUNDS
    _reg(id="MAP-NC", status="non_compliant", mitigation_summary="")
    with pytest.raises(ValueError, match="COMPLIANCE_ERR_BOUNDS_EXCEEDED"):
        compliance.execute(action="status", id="MAP-NC", status="compliant")


# ---------------------------------------------------------------------------
# B3 — audit + PEP effects (spec §7/§8): exactly one row per call
# ---------------------------------------------------------------------------

def _ring_count() -> int:
    conn = audit_client.open_db()
    try:
        return conn.execute("SELECT COUNT(*) c FROM audit_ring").fetchone()["c"]
    finally:
        conn.close()


def _mint_scope_grant(tools: list[str]) -> str:
    conn = audit_client.open_db()
    try:
        audit_client.ensure_pep_schema(conn)
        scope = {"tools": tools, "paths": [], "networks": []}
        grant_id = "gr_compliance_test_001"
        conn.execute(
            """INSERT INTO pep_grants (grant_id, issued_at, expires_at,
               issued_to, constitution_rev, scope_json, scope_hash, single_use)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (grant_id, "2026-10-01T00:00:00Z", "2199-12-31T23:59:59Z",
             "agent:test", "rev-test",
             json.dumps(scope, sort_keys=True),
             audit_client.sha256_hex(json.dumps(scope, sort_keys=True)), 0))
        audit_client.write_audit_row(conn, {
            "ts": audit_client.utcnow_iso(), "actor": "user",
            "actor_id": "tester", "tool": "pep.capability.mint",
            "command": "capability.mint",
            "args": {"grant_id": grant_id, "scope": scope}, "target": None,
            "outcome": "ok", "outcome_detail": None,
            "constitution_rev": "rev-test", "grant_token": grant_id,
            "c_flags": {"c1": False, "c2": False, "c3": False, "c4": False},
        })
        conn.commit()
    finally:
        conn.close()
    return grant_id


def test_b3_audit_and_pep_effects(store, tmp_path, monkeypatch):
    from aiosh_mcp.server import aios_compliance

    home = tmp_path / "home"
    monkeypatch.setenv("AIOSH_HOME", str(home))
    grant_id = _mint_scope_grant(["aios.compliance"])
    audit_client.default_db_path.cache_clear() if hasattr(
        audit_client.default_db_path, "cache_clear") else None

    # Read action: allowed without grant, exactly one audit row.
    n0 = _ring_count()
    r = aios_compliance(action="list")
    assert r["ok"] is True and "audit_id" in r
    assert _ring_count() == n0 + 1

    # Domain error: one outcome=error row, spec §4 envelope.
    n1 = _ring_count()
    r = aios_compliance(action="show", id="MAP-NOPE")
    assert r["ok"] is False and r["action"] == "show"
    assert "COMPLIANCESVC_ERR_NOT_FOUND" in r["error"]
    assert r["audit_id"] and _ring_count() == n1 + 1

    # Ungranted write: PEP refusal, exactly one (refusal) audit row.
    n2 = _ring_count()
    r = aios_compliance(action="register", id="MAP-GRANTED-001",
                        control_id="AC-3", framework="nist",
                        target_type="pep_gate", target_ref="gate.y",
                        status="compliant", mitigation_summary="m")
    assert r["ok"] is False
    assert _ring_count() == n2 + 1

    # Grant-gated write: the redeem-before-act gate (invariant I-2) writes its
    # redemption row, then _recorded_call writes the result row -> exactly 2
    # rows for a granted call (redemption + result). Chain-wide behavior for
    # every grant-gated tool (conformance C2 depends on the redeem row).
    n3 = _ring_count()
    r = aios_compliance(action="register", id="MAP-GRANTED-001",
                        control_id="AC-3", framework="nist",
                        target_type="pep_gate", target_ref="gate.y",
                        status="compliant", mitigation_summary="m",
                        grant_id=grant_id)
    assert r["ok"] is True and r["action"] == "register"
    assert "audit_id" in r
    assert _ring_count() == n3 + 2


# ---------------------------------------------------------------------------
# B4 — persistence (spec §5)
# ---------------------------------------------------------------------------

def test_b4_store_round_trip_byte_stable(store):
    _reg(id="MAP-BYTE-001")
    bytes1 = store.read_bytes()

    # Canonical form: UTF-8, LF only, 2-space indent, no trailing newline
    # (serde_json::to_string_pretty parity), .json key order = Rust order.
    assert b"\r" not in bytes1
    assert bytes1.startswith(b'{\n  "version": ')
    assert not bytes1.endswith(b"\n")
    snap = json.loads(bytes1.decode("utf-8"))
    assert list(snap) == ["version", "mappings", "generated_at"]
    assert list(snap["mappings"][0]) == [
        "id", "control_id", "framework", "target_type", "target_ref",
        "threat_ids", "status", "mitigation_summary", "tags",
        "created_at", "updated_at"]

    # Load -> save with no semantic change is byte-identical (round-trip).
    loaded = compliance.load_store(str(store))
    compliance.save_store(str(store), loaded)
    assert store.read_bytes() == bytes1

    # Atomic write leaves no tmp files behind.
    leftovers = [p for p in store.parent.iterdir() if ".tmp" in p.name]
    assert leftovers == []


# ---------------------------------------------------------------------------
# B5 — validation parity (spec §6)
# ---------------------------------------------------------------------------

def test_b5_validation_parity_bounds_and_transitions(store):
    compliance.validate_identifier("MAP-ok_1.2-x", "Mapping ID")
    with pytest.raises(ValueError, match="COMPLIANCE_ERR_INVALID_ID"):
        compliance.validate_identifier("bad/id", "Mapping ID")
    with pytest.raises(ValueError, match="COMPLIANCE_ERR_INVALID_ID"):
        compliance.validate_identifier("", "Mapping ID")
    with pytest.raises(ValueError, match="COMPLIANCE_ERR_BOUNDS_EXCEEDED"):
        compliance.validate_identifier("a" * 65, "Mapping ID")
    # Non-ASCII rejected even when within length (ASCII-only rule).
    with pytest.raises(ValueError, match="COMPLIANCE_ERR_INVALID_ID"):
        compliance.validate_identifier("ünïcode", "Mapping ID")

    # validate_text_length: byte-length parity (Rust str::len) + control chars
    compliance.validate_text_length("line1\nline2\ttab", 64, "Notes")
    with pytest.raises(ValueError, match="COMPLIANCE_ERR_CONTROL_CHARS"):
        compliance.validate_text_length("bell\x07", 64, "Notes")
    with pytest.raises(ValueError, match="COMPLIANCE_ERR_BOUNDS_EXCEEDED"):
        compliance.validate_text_length("é" * 40, 64, "Notes")  # 80 bytes

    # Status machine: Rust can_transition_to falls through `_ => true`.
    assert compliance.can_transition("compliant", "non_compliant") is True
    assert compliance.can_transition("not_applicable", "partially_compliant") is True

    # Canonical baseline: the four built-in mappings with exact ids.
    base = compliance.canonical_baseline()
    assert [m.id for m in base.mappings] == [
        "MAP-NIST-AC3-PEP", "MAP-NIST-AU2-RING",
        "MAP-SOC2-CC61-PEP", "MAP-CIS-CTRL6-PEP"]
    assert base.version == "1.0.0"
