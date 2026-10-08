#!/usr/bin/env python3
"""Compliance Mapping — MCP/API surface Test Scaffold (T-02895).

Contract: docs/tasks/evidence/T-02894-spec.md (normative).
Structure only: S-* tests verify the scaffold itself and pass now;
B-* tests are behavioral stubs that fail loudly until T-02896 (Implementation).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from aiosh_mcp import compliance  # noqa: E402


# ---------------------------------------------------------------------------
# S-* — scaffold structure (green now)
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
    # every alias resolves into the closed set
    assert set(compliance.FRAMEWORK_ALIASES.values()) <= set(compliance.FRAMEWORKS)
    assert set(compliance.STATUS_ALIASES.values()) <= set(compliance.STATUSES)


def test_s3_action_vocabulary_and_gating_split():
    """Spec §2/§8: seven verbs; exactly three are write actions."""
    assert set(compliance.ACTIONS) == {
        "list", "show", "register", "status", "assess", "check-pep", "init"}
    assert set(compliance.WRITE_ACTIONS) == {"register", "status", "init"}
    assert set(compliance.READ_ACTIONS) == {
        "list", "show", "assess", "check-pep"}
    assert not set(compliance.READ_ACTIONS) & set(compliance.WRITE_ACTIONS)


def test_s4_entry_field_order_matches_rust():
    """Byte-stable round-trip (spec §5) requires the Rust struct order."""
    assert [f for f in compliance.ComplianceMappingEntry.__dataclass_fields__] == [
        "id", "control_id", "framework", "target_type", "target_ref",
        "threat_ids", "status", "mitigation_summary", "tags",
        "created_at", "updated_at"]


def test_s5_interfaces_exist_and_fail_loudly():
    """Scaffold contract: every interface is present and raises until T-02896."""
    for name in ("validate_identifier", "validate_title", "validate_text_length",
                 "parse_framework", "parse_status", "validate_path",
                 "load_store", "save_store", "init_store",
                 "list_mappings", "get_mapping", "register_mapping",
                 "update_status", "assess_framework",
                 "verify_pep_coverage", "uncovered_pep_gates", "execute"):
        fn = getattr(compliance, name)
        assert callable(fn), name
        with pytest.raises(NotImplementedError):
            fn(*( [None] * (fn.__code__.co_argcount or 1) ))


# ---------------------------------------------------------------------------
# B-* — behavioral stubs (fail loudly until T-02896 IMPLEMENTATION)
# ---------------------------------------------------------------------------

def test_b1_happy_path_list_show_register():
    pytest.fail("T-02896 IMPLEMENTATION: register + list + show happy path "
                "(spec §3 envelope with audit_id)")


def test_b2_failure_codes_match_spec_table():
    pytest.fail("T-02896 IMPLEMENTATION: PARAM_INVALID / DUPLICATE_ID / "
                "INVALID_STATUS_TRANSITION / NOT_FOUND / BOUNDS error codes (spec §4)")


def test_b3_audit_row_per_call_including_refusals():
    pytest.fail("T-02896 IMPLEMENTATION: exactly one audit row per call via "
                "_recorded_call; PEP refusal rows for write actions (spec §7/§8)")


def test_b4_store_round_trip_byte_stable():
    pytest.fail("T-02896 IMPLEMENTATION: canonical store form — UTF-8/LF/2-space, "
                "key order preserved, atomic .tmp+replace (spec §5)")


def test_b5_validation_parity_bounds_and_transitions():
    pytest.fail("T-02896 IMPLEMENTATION: bounds + status machine parity with "
                "compliance_data_model.rs (spec §6)")
