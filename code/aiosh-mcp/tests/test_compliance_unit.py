#!/usr/bin/env python3
"""Compliance Mapping MCP/API surface — focused unit tests (T-02897).

Contract: docs/tasks/evidence/T-02894-spec.md (normative).
Complements test_compliance_surface.py (T-02895/T-02896) with unit-level
coverage per T-02897:

  * valid input        — envelopes, alias canonicalization, persistence
  * invalid input      — spec §4 error codes for every failure class
  * boundary values    — byte-length and count limits at N / N+1, store
                         size cap, catalog capacity, path depth
  * primary failure    — an ungranted write is refused at the PEP gate and
                         the store file is left untouched (fail-closed)

Only observable behavior is asserted: return envelopes, store file bytes,
and audit rows. No implementation details.

Run standalone:
    python3 code/aiosh-mcp/tests/test_compliance_unit.py
Or under pytest:
    python3 -m pytest code/aiosh-mcp/tests/test_compliance_unit.py -q
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aiosh_mcp import audit_client, compliance  # noqa: E402

PASS = "[PASS]"
FAIL = "[FAIL]"


# ---------------------------------------------------------------------------
# Harness (no pytest dependency; pytest still collects test_* functions)
# ---------------------------------------------------------------------------

@contextmanager
def temp_store():
    """Point the compliance store at a fresh temp file; always restore."""
    with tempfile.TemporaryDirectory(prefix="compliance-unit-") as td:
        path = os.path.join(td, "compliance_map.json")
        old = os.environ.get("AIOSH_COMPLIANCE_MAP_PATH")
        os.environ["AIOSH_COMPLIANCE_MAP_PATH"] = path
        try:
            yield path
        finally:
            if old is None:
                os.environ.pop("AIOSH_COMPLIANCE_MAP_PATH", None)
            else:
                os.environ["AIOSH_COMPLIANCE_MAP_PATH"] = old


@contextmanager
def temp_home():
    """Isolated AIOSH_HOME so audit rows never touch a real database."""
    with tempfile.TemporaryDirectory(prefix="compliance-unit-home-") as td:
        old = os.environ.get("AIOSH_HOME")
        os.environ["AIOSH_HOME"] = td
        try:
            yield td
        finally:
            if old is None:
                os.environ.pop("AIOSH_HOME", None)
            else:
                os.environ["AIOSH_HOME"] = old


def expect_error(code, fn, *args, **kwargs):
    """fn must raise ValueError('CODE: ...') with exactly the given code."""
    try:
        fn(*args, **kwargs)
    except ValueError as exc:
        assert str(exc).startswith(f"{code}: "), (
            f"expected {code}, got: {exc}")
        return exc
    raise AssertionError(f"expected {code} from {fn.__name__}, but it succeeded")


def _reg(**kw):
    base = dict(action="register", control_id="AC-2", framework="nist",
                target_type="pep_gate", target_ref="pep_enforce_gate",
                status="non_compliant")
    base.update(kw)
    return compliance.execute(**base)


def _ring_count() -> int:
    conn = audit_client.open_db()
    try:
        return conn.execute("SELECT COUNT(*) c FROM audit_ring").fetchone()["c"]
    finally:
        conn.close()


def _store_ids(path) -> list[str]:
    with open(path, encoding="utf-8") as fh:
        return [m["id"] for m in json.load(fh)["mappings"]]


# ---------------------------------------------------------------------------
# Valid input
# ---------------------------------------------------------------------------

def test_register_show_roundtrip_envelope():
    """register -> show returns the same persisted mapping (spec §3)."""
    with temp_store() as path:
        res = _reg(id="MAP-UNIT-001")
        assert res["ok"] is True and res["action"] == "register"
        m = res["mapping"]
        assert m["id"] == "MAP-UNIT-001"
        assert m["framework"] == "nist_sp_800_53_rev5"
        assert m["status"] == "non_compliant"          # default when omitted
        assert m["created_at"] == m["updated_at"] and m["created_at"]

        shown = compliance.execute(action="show", id="MAP-UNIT-001")
        assert shown["ok"] is True and shown["action"] == "show"
        assert shown["mapping"] == m
        assert "MAP-UNIT-001" in _store_ids(path)


def test_register_onto_missing_store_keeps_baseline():
    """CLI parity: a missing store loads the canonical baseline (4 entries),
    so the first register persists baseline + new mapping."""
    with temp_store() as path:
        _reg(id="MAP-NEW-001")
        ids = _store_ids(path)
        assert len(ids) == 5 and "MAP-NEW-001" in ids
        assert "MAP-NIST-AC3-PEP" in ids


def test_read_actions_never_create_or_touch_store():
    """Reads work against the baseline without creating the file (spec §5)."""
    with temp_store() as path:
        assert compliance.execute(action="list")["count"] == 4
        assert compliance.execute(action="assess")["report"]["total_mappings"] == 4
        pep = compliance.execute(action="check-pep", gate_id="pep_enforce_gate")
        assert pep["covered"] is True and pep["uncovered_required"] == []
        assert not os.path.exists(path)


def test_init_creates_baseline_file_then_refuses():
    with temp_store() as path:
        res = compliance.execute(action="init")
        assert res["ok"] is True and res["initialized"] is True
        assert res["version"] == "1.0.0" and res["count"] == 4
        assert os.path.exists(path)
        expect_error(compliance.STORE_EXISTS, compliance.execute, action="init")


def test_status_change_persists_to_store():
    with temp_store() as path:
        _reg(id="MAP-STAT-001")
        res = compliance.execute(action="status", id="MAP-STAT-001",
                                 status="compliant", reason="unit rationale")
        assert res["ok"] is True and res["mapping"]["status"] == "compliant"
        obj = json.loads(Path(path).read_text(encoding="utf-8"))
        entry = next(m for m in obj["mappings"] if m["id"] == "MAP-STAT-001")
        assert entry["status"] == "compliant"


def test_framework_and_status_aliases_canonicalize():
    with temp_store():
        res = _reg(id="MAP-ALIAS-001", framework="NIST", status="partial")
        assert res["mapping"]["framework"] == "nist_sp_800_53_rev5"
        assert res["mapping"]["status"] == "partially_compliant"
        assert compliance.parse_framework("SOC2") == "soc2_type2"
        assert compliance.parse_status("NonCompliant") == "non_compliant"


def test_assess_report_math_and_filters():
    with temp_store():
        _reg(id="MAP-OK-001", status="compliant", mitigation_summary="m",
             framework="soc2", control_id="CC1")
        _reg(id="MAP-GAP-001", framework="pci", control_id="REQ-1")
        rep = compliance.execute(action="assess")["report"]
        # baseline: 4 compliant; new: 1 compliant + 1 non_compliant
        assert rep["total_mappings"] == 6
        assert rep["compliant_count"] == 5 and rep["non_compliant_count"] == 1
        assert rep["gap_control_ids"] == ["REQ-1"]
        assert abs(rep["compliance_percentage"] - (5 / 6) * 100.0) < 1e-9
        # unknown framework -> empty set -> 100.0 (Rust parity)
        empty = compliance.execute(action="assess", framework="hipaa")["report"]
        assert empty["total_mappings"] == 0 and empty["compliance_percentage"] == 100.0


def test_check_pep_uncovered_gate_reported():
    with temp_store():
        res = compliance.execute(action="check-pep", gate_id="gate_missing")
        assert res["ok"] is True and res["covered"] is False
        assert res["uncovered_required"] == ["gate_missing"]


# ---------------------------------------------------------------------------
# Invalid input (spec §4 error-code table)
# ---------------------------------------------------------------------------

def test_unknown_action_param_invalid():
    expect_error(compliance.PARAM_INVALID, compliance.execute, action="frobnicate")


def test_missing_required_params_param_invalid():
    with temp_store():
        cases = [
            dict(action="show"),
            dict(action="status", id="MAP-X"),
            dict(action="check-pep"),
            dict(action="register", control_id="AC-1", framework="nist",
                 target_type="pep_gate", target_ref="g"),
            dict(action="register", id="MAP-X", framework="nist",
                 target_type="pep_gate", target_ref="g"),
            dict(action="register", id="MAP-X", control_id="AC-1",
                 target_type="pep_gate", target_ref="g"),
            dict(action="register", id="MAP-X", control_id="AC-1",
                 framework="nist", target_ref="g"),
            dict(action="register", id="MAP-X", control_id="AC-1",
                 framework="nist", target_type="pep_gate"),
        ]
        for kw in cases:
            expect_error(compliance.PARAM_INVALID, compliance.execute, **kw)
        assert not os.path.exists(os.environ["AIOSH_COMPLIANCE_MAP_PATH"])


def test_unknown_enum_values_param_invalid():
    with temp_store():
        expect_error(compliance.PARAM_INVALID, _reg,
                     id="MAP-BAD-001", framework="gdpr")
        expect_error(compliance.PARAM_INVALID, _reg,
                     id="MAP-BAD-002", status="compromised")
        expect_error(compliance.PARAM_INVALID, compliance.execute,
                     action="list", status="meh")


def test_invalid_identifier_codes():
    with temp_store():
        expect_error(compliance.COMPLIANCE_ERR_INVALID_ID, _reg,
                     id="MAP has space")
        expect_error(compliance.COMPLIANCE_ERR_INVALID_ID, _reg,
                     id="MAP/slash")
        expect_error(compliance.COMPLIANCE_ERR_INVALID_ID, _reg,
                     id="   ")
        expect_error(compliance.COMPLIANCE_ERR_INVALID_ID, _reg,
                     id="MAP-CI-001",
                     control_id="AC\u20131")  # en-dash is not ASCII alnum


def test_empty_target_ref_missing_substrate_ref():
    """Whitespace target_ref reaches the Rust-parity validator (not PARAM_INVALID)."""
    with temp_store():
        e = expect_error(compliance.COMPLIANCE_ERR_MISSING_SUBSTRATE_REF,
                         _reg, id="MAP-REF-001", target_ref="   ")
        assert "target ref" in str(e).lower()


def test_duplicate_id_rejected_store_unchanged():
    with temp_store() as path:
        _reg(id="MAP-DUP-001")
        before = Path(path).read_bytes()
        expect_error(compliance.COMPLIANCE_ERR_DUPLICATE_ID, _reg,
                     id="MAP-DUP-001")
        assert Path(path).read_bytes() == before  # failed write leaves file intact


def test_show_and_status_not_found():
    with temp_store():
        expect_error(compliance.COMPLIANCESVC_ERR_NOT_FOUND,
                     compliance.execute, action="show", id="MAP-NOPE")
        expect_error(compliance.COMPLIANCESVC_ERR_NOT_FOUND,
                     compliance.execute, action="status", id="MAP-NOPE",
                     status="compliant", reason="r")


def test_compliant_transition_requires_summary_or_reason():
    with temp_store():
        expect_error(compliance.COMPLIANCE_ERR_BOUNDS_EXCEEDED, _reg,
                     id="MAP-C-001", status="compliant")
        _reg(id="MAP-C-002", status="compliant", mitigation_summary="mitigated")
        # entry without summary: reason unlocks the transition (parity guard)
        _reg(id="MAP-C-003")
        expect_error(compliance.COMPLIANCE_ERR_BOUNDS_EXCEEDED,
                     compliance.execute, action="status", id="MAP-C-003",
                     status="compliant")
        ok = compliance.execute(action="status", id="MAP-C-003",
                                status="compliant", reason="ticket-1")
        assert ok["mapping"]["status"] == "compliant"


# ---------------------------------------------------------------------------
# Boundary values (N accepted, N+1 rejected)
# ---------------------------------------------------------------------------

def test_identifier_byte_length_boundary():
    with temp_store():
        _reg(id="M" * 64)                      # exactly 64 bytes: accepted
        expect_error(compliance.COMPLIANCE_ERR_BOUNDS_EXCEEDED, _reg,
                     id="M" * 65)              # 65 bytes: rejected
        # byte semantics, not character count: 33 * 'é' = 66 UTF-8 bytes
        expect_error(compliance.COMPLIANCE_ERR_BOUNDS_EXCEEDED,
                     compliance.validate_identifier, "é" * 33, "Mapping ID")


def test_title_byte_length_boundary_and_control_chars():
    expect_error(compliance.COMPLIANCE_ERR_BOUNDS_EXCEEDED,
                 compliance.validate_title, "T" * 129, "Title")
    # exactly 128 accepted; control char rejected even within length
    compliance.validate_title("T" * 128, "Title")
    expect_error(compliance.COMPLIANCE_ERR_CONTROL_CHARS,
                 compliance.validate_title, "line\nbreak", "Title")
    expect_error(compliance.COMPLIANCE_ERR_INVALID_TITLE,
                 compliance.validate_title, "   ", "Title")


def test_text_length_boundary_and_control_char_rules():
    compliance.validate_text_length("N" * 2048, compliance.MAX_COMPLIANCE_NOTES_LEN, "Notes")
    expect_error(compliance.COMPLIANCE_ERR_BOUNDS_EXCEEDED,
                 compliance.validate_text_length, "N" * 2049,
                 compliance.MAX_COMPLIANCE_NOTES_LEN, "Notes")
    # \n \r \t are allowed in free text; NUL is not
    compliance.validate_text_length("a\nb\tc\r", 2048, "Notes")
    expect_error(compliance.COMPLIANCE_ERR_CONTROL_CHARS,
                 compliance.validate_text_length, "a\x00b", 2048, "Notes")


def test_threat_and_tag_count_boundary():
    base = dict(id="MAP-CNT-001", control_id="AC-9", framework="nist",
                target_type="pep_gate", target_ref="gate_cnt",
                status="non_compliant")
    compliance.build_entry(threat_ids=["T-%02d" % i for i in range(16)],
                           tags=["tag%d" % i for i in range(16)], **base)
    expect_error(compliance.COMPLIANCE_ERR_BOUNDS_EXCEEDED, compliance.build_entry,
                 threat_ids=["T-%02d" % i for i in range(17)], **base)
    expect_error(compliance.COMPLIANCE_ERR_BOUNDS_EXCEEDED, compliance.build_entry,
                 tags=["tag%d" % i for i in range(17)], **base)


def test_catalog_capacity_boundary():
    snap = compliance.ComplianceCatalogSnapshot()
    snap.mappings = [compliance.ComplianceMappingEntry(id="M%04d" % i)
                     for i in range(compliance.MAX_COMPLIANCE_ENTRIES_CAPACITY - 1)]
    entry = compliance.ComplianceMappingEntry(id="M-LAST")
    compliance.register_mapping(snap, entry)                    # 1023 -> 1024: ok
    assert len(snap.mappings) == compliance.MAX_COMPLIANCE_ENTRIES_CAPACITY
    expect_error(compliance.COMPLIANCE_ERR_BOUNDS_EXCEEDED,
                 compliance.register_mapping, snap,
                 compliance.ComplianceMappingEntry(id="M-OVERFLOW"))


def test_store_file_size_cap_boundary():
    with temp_store() as path:
        with open(path, "wb") as fh:
            fh.write(b"x" * (compliance.MAX_COMPLIANCE_STORE_SIZE + 1))
        expect_error(compliance.COMPLIANCESVC_ERR_FILE_SIZE,
                     compliance.execute, action="list")


def test_corrupt_store_parse_error():
    with temp_store() as path:
        Path(path).write_text("{not json", encoding="utf-8")
        expect_error(compliance.COMPLIANCESVC_ERR_PARSE,
                     compliance.execute, action="list")


def test_path_validation_boundaries():
    ok = os.path.join("docs", "compliance_map.json")
    assert compliance.validate_path(ok) == ok
    for bad in ("", "map.txt", ".json", "../evil.json", "aa/..\\x.json"):
        expect_error(compliance.COMPLIANCESVC_ERR_PATH_TRAVERSAL,
                     compliance.validate_path, bad)
    deep = "/".join(["d"] * 16) + "/map.json"   # 17 components: rejected
    expect_error(compliance.COMPLIANCESVC_ERR_PATH_TRAVERSAL,
                 compliance.validate_path, deep)
    shallow = "/".join(["d"] * 15) + "/map.json"  # 16 components: accepted
    compliance.validate_path(shallow)


def test_obj_to_snapshot_parse_errors():
    expect_error(compliance.COMPLIANCESVC_ERR_PARSE,
                 compliance._obj_to_snapshot, {"version": "1.0.0"})
    expect_error(compliance.COMPLIANCESVC_ERR_PARSE,
                 compliance._obj_to_snapshot,
                 {"version": "1.0.0", "mappings": "nope", "generated_at": "t"})
    expect_error(compliance.COMPLIANCESVC_ERR_PARSE,
                 compliance._obj_to_snapshot,
                 {"version": "1.0.0", "mappings": ["not-an-object"],
                  "generated_at": "t"})


def test_load_store_missing_file_is_io_error():
    with temp_store() as path:
        expect_error(compliance.COMPLIANCESVC_ERR_IO, compliance.load_store, path)


# ---------------------------------------------------------------------------
# Hardening (T-02900) — bounded read, payload cap, tmp cleanup, envelopes
# ---------------------------------------------------------------------------


def test_load_bounded_read_covers_size_race():
    """File grows between getsize and read (TOCTOU): the bounded read must
    stop at cap+1 and refuse FILE_SIZE instead of loading unbounded."""
    old_cap = compliance.MAX_COMPLIANCE_STORE_SIZE
    compliance.MAX_COMPLIANCE_STORE_SIZE = 64
    try:
        with temp_store() as path:
            with open(path, "wb") as fh:
                fh.write(b"x" * 200)          # 200 bytes > 64-byte cap
            real_getsize = os.path.getsize
            os.path.getsize = lambda _p: 0    # race: size observed small
            try:
                expect_error(compliance.COMPLIANCESVC_ERR_FILE_SIZE,
                             compliance.load_store, path)
            finally:
                os.path.getsize = real_getsize
    finally:
        compliance.MAX_COMPLIANCE_STORE_SIZE = old_cap


def test_save_payload_over_cap_refused_no_file_no_tmp():
    """save_store refuses a payload above the read cap BEFORE any file
    handle exists: FILE_SIZE raised, no store file, no tmp leak — a store
    can never be written that load_store (or the Rust CLI) would reject."""
    old_cap = compliance.MAX_COMPLIANCE_STORE_SIZE
    compliance.MAX_COMPLIANCE_STORE_SIZE = 64
    try:
        with temp_store() as path:
            snap = compliance.canonical_baseline()   # payload far above 64 B
            expect_error(compliance.COMPLIANCESVC_ERR_FILE_SIZE,
                         compliance.save_store, path, snap)
            assert not os.path.exists(path)
            td = os.path.dirname(path)
            assert [n for n in os.listdir(td) if ".tmp." in n] == []
    finally:
        compliance.MAX_COMPLIANCE_STORE_SIZE = old_cap


def test_save_replace_failure_unlinks_tmp_and_raises_io():
    """Mid-write failure (os.replace raises): explicit FILE_ERR_IO, tmp
    file cleaned up, no partial store at the target path."""
    with temp_store() as path:
        real_replace = os.replace

        def _boom(_src, _dst):
            raise OSError("simulated replace failure")

        os.replace = _boom
        try:
            expect_error(compliance.COMPLIANCESVC_ERR_IO,
                         compliance.save_store, path,
                         compliance.canonical_baseline())
        finally:
            os.replace = real_replace
        assert not os.path.exists(path)
        td = os.path.dirname(path)
        assert [n for n in os.listdir(td) if ".tmp." in n] == []


def test_load_invalid_utf8_is_parse_envelope():
    """Invalid UTF-8 bytes surface as an explicit PARSE error from
    load_store — never a raw UnicodeDecodeError escape (regression guard
    for the bytes-mode bounded read)."""
    with temp_store() as path:
        with open(path, "wb") as fh:
            fh.write(b"{\xff\xfe not utf8")
        expect_error(compliance.COMPLIANCESVC_ERR_PARSE,
                     compliance.load_store, path)


def test_status_transitions_follow_rust_fallback():
    """Rust parity: enumerated arms are documentation; `_ => true` means every
    transition is legal — including pairs absent from STATUS_TRANSITIONS."""
    assert compliance.can_transition("compliant", "not_applicable") is True
    assert compliance.can_transition("non_compliant", "non_compliant") is True
    snap = compliance.ComplianceCatalogSnapshot()
    snap.mappings.append(compliance.ComplianceMappingEntry(
        id="MAP-TR-001", status="compliant", mitigation_summary="m"))
    entry = compliance.update_status(snap, "MAP-TR-001", "not_applicable")
    assert entry.status == "not_applicable"


def test_pep_coverage_exact_rules():
    def entry(tt, ref, st):
        return compliance.ComplianceMappingEntry(
            id="X", target_type=tt, target_ref=ref, status=st)

    snap = compliance.ComplianceCatalogSnapshot()
    snap.mappings = [entry("pep_gate", "g1", "compliant"),
                     entry("pep_gate", "g2", "partially_compliant"),
                     entry("pep_gate", "g3", "non_compliant"),
                     entry("audit_ring", "g4", "compliant")]
    assert compliance.verify_pep_coverage(snap, "g1") is True
    assert compliance.verify_pep_coverage(snap, "g2") is True    # partial covers
    assert compliance.verify_pep_coverage(snap, "g3") is False   # non-compliant does not
    assert compliance.verify_pep_coverage(snap, "g4") is False   # wrong target type
    assert compliance.verify_pep_coverage(snap, "g5") is False   # unknown gate
    assert compliance.uncovered_pep_gates(snap, ["g1", "g3", "g5"]) == ["g3", "g5"]


# ---------------------------------------------------------------------------
# Primary failure mode: ungranted write refused at the PEP gate, fail-closed
# ---------------------------------------------------------------------------

def test_primary_ungranted_write_refused_store_untouched():
    """The surface's primary failure: a write without a capability grant must
    be refused (gate=pep), must NOT touch the store, and must leave exactly
    one refusal audit row (spec §7/§8)."""
    from aiosh_mcp.server import aios_compliance

    with temp_home(), temp_store() as path:
        n0 = _ring_count()
        r = aios_compliance(action="register", id="MAP-NOGRANT-001",
                            control_id="AC-1", framework="nist",
                            target_type="pep_gate", target_ref="gate.unit",
                            status="compliant", mitigation_summary="m")
        assert r["ok"] is False
        assert r.get("gate") == "pep"
        assert "requires explicit PEP grant" in r.get("reason", "")
        assert r.get("audit_id")
        # fail-closed: no store file was created by the refused write
        assert not os.path.exists(path)
        # exactly one refusal row
        assert _ring_count() == n0 + 1
        conn = audit_client.open_db()
        try:
            row = conn.execute(
                "SELECT outcome, tool FROM audit_ring ORDER BY id DESC LIMIT 1"
            ).fetchone()
        finally:
            conn.close()
        assert row["outcome"] == "refused" and row["tool"] == "aios.compliance"

    # reads remain available without a grant (fail-closed applies to writes)
    with temp_home(), temp_store():
        r = aios_compliance(action="list")
        assert r["ok"] is True and r["count"] == 4


# ---------------------------------------------------------------------------
# Standalone runner (pytest collects the same functions)
# ---------------------------------------------------------------------------

def main() -> int:
    tests = [(name, fn) for name, fn in list(globals().items())
             if name.startswith("test_") and callable(fn)]
    failed = []
    for name, fn in tests:
        try:
            fn()
            print(f"{PASS} {name}")
        except Exception as exc:  # noqa: BLE001 — report every failure
            failed.append(name)
            print(f"{FAIL} {name}: {type(exc).__name__}: {exc}")
    print("-" * 60)
    if failed:
        print(f"{len(failed)}/{len(tests)} FAILED: {', '.join(failed)}")
        return 1
    print(f"ALL {len(tests)} T-02897 UNIT TESTS PASSED!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
