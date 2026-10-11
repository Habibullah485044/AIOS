"""Compliance Mapping Automated Unit Test Suite (T-02917).

Contract: docs/tasks/evidence/T-02914-spec.md.
Validates:
  1. Valid input: All 6 frameworks, valid transitions, assessment reports.
  2. Invalid input: Rejection of bad actions, missing refs, bad frameworks, missing justifications.
  3. Boundary values: Exact limits for ID (64), title (128), text (2048), arrays (16).
  4. Primary failure mode: Traversal rejection, fail-closed atomic store integrity.
"""

from __future__ import annotations

import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path

import pytest

from aiosh_mcp import compliance
from aiosh_mcp import compliance_config


@contextmanager
def temp_store():
    with tempfile.TemporaryDirectory(prefix="compliance-auto-unit-") as td:
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


# ---------------------------------------------------------------------------
# 1. Valid Input Coverage
# ---------------------------------------------------------------------------

def test_valid_input_all_frameworks_register_and_show():
    """Verify registration and lookup across all supported frameworks."""
    with temp_store() as path:
        compliance.execute(action="init")
        for idx, fw in enumerate(compliance.FRAMEWORKS):
            mid = f"VAL-FW-{idx}"
            res = compliance.execute(
                action="register",
                id=mid,
                control_id=f"CTRL-{idx}",
                framework=fw,
                target_type="pep_gate",
                target_ref=f"pep.gate.{idx}",
                status="partially_compliant",
                mitigation_summary=f"Rollout for {fw}",
            )
            assert res["ok"] is True
            assert res["mapping"]["framework"] == fw

            shown = compliance.execute(action="show", id=mid)
            assert shown["ok"] is True
            assert shown["mapping"]["id"] == mid


def test_valid_input_status_transition_sequence():
    """Verify legal status transitions: non_compliant -> partial -> compliant."""
    with temp_store():
        compliance.execute(action="init")
        compliance.execute(
            action="register",
            id="TR-001",
            control_id="AC-1",
            framework="soc2_type2",
            target_type="pep_gate",
            target_ref="pep.auth",
            status="non_compliant",
        )

        # Transition to partially_compliant
        st1 = compliance.execute(action="status", id="TR-001", status="partially_compliant", reason="Testing step")
        assert st1["ok"] is True
        assert st1["mapping"]["status"] == "partially_compliant"

        # Transition to compliant with explanation
        st2 = compliance.execute(action="status", id="TR-001", status="compliant", reason="Validated against audit")
        assert st2["ok"] is True
        assert st2["mapping"]["status"] == "compliant"


def test_valid_input_assessment_and_gap_computation():
    """Verify assessment calculation with non-empty gaps."""
    snap = compliance.ComplianceCatalogSnapshot()
    snap.mappings = [
        compliance.build_entry(id="C1", control_id="AC-1", framework="nist_sp_800_53_rev5", target_type="pep_gate", target_ref="p1", status="compliant", mitigation_summary="Done"),
        compliance.build_entry(id="C2", control_id="AC-2", framework="nist_sp_800_53_rev5", target_type="pep_gate", target_ref="p2", status="partially_compliant"),
        compliance.build_entry(id="C3", control_id="AC-3", framework="nist_sp_800_53_rev5", target_type="pep_gate", target_ref="p3", status="non_compliant"),
        compliance.build_entry(id="C4", control_id="AC-4", framework="nist_sp_800_53_rev5", target_type="pep_gate", target_ref="p4", status="not_applicable"),
    ]
    rep = compliance.assess_framework(snap, framework="nist_sp_800_53_rev5")
    assert rep.total_mappings == 4
    assert rep.compliant_count == 1
    assert rep.partially_compliant_count == 1
    assert rep.non_compliant_count == 1
    assert rep.not_applicable_count == 1
    assert rep.compliance_percentage == 25.0
    assert rep.gap_control_ids == ["AC-2", "AC-3"]


# ---------------------------------------------------------------------------
# 2. Invalid Input Coverage
# ---------------------------------------------------------------------------

def test_invalid_input_unknown_action():
    with pytest.raises(ValueError) as exc:
        compliance.execute(action="destroy-all")
    assert compliance.PARAM_INVALID in str(exc.value)


def test_invalid_input_bad_framework():
    with temp_store():
        compliance.execute(action="init")
        with pytest.raises(ValueError) as exc:
            compliance.execute(
                action="register",
                id="BAD-FW",
                control_id="C1",
                framework="unknown_framework_xyz",
                target_type="pep_gate",
                target_ref="pep.1",
            )
        assert compliance.PARAM_INVALID in str(exc.value)


def test_invalid_input_missing_substrate_ref():
    with temp_store():
        compliance.execute(action="init")
        with pytest.raises(ValueError) as exc:
            compliance.execute(
                action="register",
                id="BAD-REF",
                control_id="C1",
                framework="soc2_type2",
                target_type="pep_gate",
                target_ref="   ",
            )
        assert compliance.COMPLIANCE_ERR_MISSING_SUBSTRATE_REF in str(exc.value)


def test_invalid_input_compliant_without_mitigation():
    """Fail closed when registering or updating to compliant without summary."""
    with temp_store():
        compliance.execute(action="init")
        with pytest.raises(ValueError) as exc:
            compliance.execute(
                action="register",
                id="BAD-COMPL",
                control_id="C1",
                framework="soc2_type2",
                target_type="pep_gate",
                target_ref="pep.1",
                status="compliant",
                mitigation_summary="",
            )
        assert compliance.COMPLIANCE_ERR_BOUNDS_EXCEEDED in str(exc.value)


def test_invalid_input_show_nonexistent_id():
    with temp_store():
        compliance.execute(action="init")
        with pytest.raises(ValueError) as exc:
            compliance.execute(action="show", id="NONEXISTENT-ID")
        assert compliance.COMPLIANCESVC_ERR_NOT_FOUND in str(exc.value)


# ---------------------------------------------------------------------------
# 3. Boundary Values Coverage
# ---------------------------------------------------------------------------

def test_boundary_values_identifier_limits():
    """ID boundary: 64 characters allowed; 65 characters rejected."""
    id_64 = "A" * 64
    assert compliance.validate_identifier(id_64, "id") == id_64

    id_65 = "A" * 65
    with pytest.raises(ValueError) as exc:
        compliance.validate_identifier(id_65, "id")
    assert compliance.COMPLIANCE_ERR_BOUNDS_EXCEEDED in str(exc.value)


def test_boundary_values_title_limits():
    """Title boundary: 128 bytes allowed; 129 bytes rejected."""
    title_128 = "T" * 128
    assert compliance.validate_title(title_128, "title") == title_128

    title_129 = "T" * 129
    with pytest.raises(ValueError) as exc:
        compliance.validate_title(title_129, "title")
    assert compliance.COMPLIANCE_ERR_BOUNDS_EXCEEDED in str(exc.value)


def test_boundary_values_text_limits():
    """Description / text boundary: 2048 bytes allowed; 2049 bytes rejected."""
    text_2048 = "D" * 2048
    assert compliance.validate_text_length(text_2048, compliance.MAX_COMPLIANCE_DESC_LEN, "desc") == text_2048

    text_2049 = "D" * 2049
    with pytest.raises(ValueError) as exc:
        compliance.validate_text_length(text_2049, compliance.MAX_COMPLIANCE_DESC_LEN, "desc")
    assert compliance.COMPLIANCE_ERR_BOUNDS_EXCEEDED in str(exc.value)


def test_boundary_values_array_capacity_limits():
    """Threat IDs / Tags boundary: 16 allowed; 17 rejected."""
    t16 = [f"threat_{i}" for i in range(16)]
    e16 = compliance.build_entry(
        id="ARRAY-16", control_id="AC-1", framework="soc2_type2",
        target_type="pep_gate", target_ref="pep.1", status="non_compliant",
        threat_ids=t16,
    )
    assert len(e16.threat_ids) == 16

    t17 = [f"threat_{i}" for i in range(17)]
    with pytest.raises(ValueError) as exc:
        compliance.build_entry(
            id="ARRAY-17", control_id="AC-1", framework="soc2_type2",
            target_type="pep_gate", target_ref="pep.1", status="non_compliant",
            threat_ids=t17,
        )
    assert compliance.COMPLIANCE_ERR_BOUNDS_EXCEEDED in str(exc.value)


# ---------------------------------------------------------------------------
# 4. Primary Failure Mode Coverage
# ---------------------------------------------------------------------------

def test_primary_failure_path_traversal_refusal():
    """Path traversal is refused fail-closed; store file is never written."""
    traversal_paths = [
        "../escaped_store.json",
        "../../etc/passwd.json",
        "docs/../../secret.json",
        "nested/../../../traversal.json",
    ]
    for p in traversal_paths:
        with pytest.raises(ValueError) as exc:
            compliance.validate_path(p)
        assert compliance.COMPLIANCESVC_ERR_PATH_TRAVERSAL in str(exc.value)


def test_primary_failure_atomic_integrity_on_write_refusal():
    """Failed write keeps original store file bitwise unchanged."""
    with temp_store() as path:
        compliance.execute(action="init")
        with open(path, "rb") as fh:
            before_bytes = fh.read()

        # Attempt to register duplicate or invalid entry
        with pytest.raises(ValueError):
            compliance.execute(
                action="register",
                id="MAP-NIST-AC3-PEP",  # already exists in baseline
                control_id="AC-3",
                framework="nist_sp_800_53_rev5",
                target_type="pep_gate",
                target_ref="pep.dup",
            )

        with open(path, "rb") as fh:
            after_bytes = fh.read()

        assert before_bytes == after_bytes
