"""Unit tests for Compliance Mapping Security Policy (T-02927).

Asserts COMPLIANCEPOL1..COMPLIANCEPOL7 invariants, evaluation verdicts,
boundary conditions, and persistence across happy/negative paths.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
import pytest

from aiosh_mcp.compliance import (
    ComplianceMappingEntry,
    ComplianceAssessmentReport,
)
from aiosh_mcp.compliance_policy import (
    ComplianceSecurityPolicy,
    CompliancePolicyMode,
    CompliancePolicyVerdict,
    COMPLIANCEPOL_ERR_VALIDATION,
    COMPLIANCEPOL_ERR_THREAT_REQUIRED,
    COMPLIANCEPOL_ERR_MITIGATION_REQUIRED,
    COMPLIANCEPOL_ERR_FRAMEWORK_PROHIBITED,
    COMPLIANCEPOL_ERR_THRESHOLD_UNMET,
    COMPLIANCEPOL_ERR_CAPACITY_EXCEEDED,
    COMPLIANCEPOL_ERR_OVERRIDE_FORBIDDEN,
    COMPLIANCEPOL_ERR_IO,
)


def _make_entry(
    entry_id: str = "map-01",
    framework: str = "nist_sp_800_53_rev5",
    threat_ids: list[str] | None = None,
    status: str = "non_compliant",
    mitigation: str = "",
) -> ComplianceMappingEntry:
    return ComplianceMappingEntry(
        id=entry_id,
        control_id="AC-1",
        framework=framework,
        target_type="pep_gate",
        target_ref="pep:gate:access",
        threat_ids=threat_ids if threat_ids is not None else ["THREAT-1"],
        status=status,
        mitigation_summary=mitigation,
        tags=["access_control"],
    )


def test_default_policy_validation():
    policy = ComplianceSecurityPolicy()
    policy.validate()
    assert policy.version == "1.0.0"
    assert policy.mode == CompliancePolicyMode.ENFORCING
    assert policy.min_compliant_percentage == 80.0
    assert policy.max_catalog_mappings == 1024


def test_version_validation_negative():
    policy = ComplianceSecurityPolicy(version="")
    with pytest.raises(ValueError, match=COMPLIANCEPOL_ERR_VALIDATION):
        policy.validate()

    policy2 = ComplianceSecurityPolicy(version="2.0.0")
    with pytest.raises(ValueError, match=COMPLIANCEPOL_ERR_VALIDATION):
        policy2.validate()


def test_bounds_validation_negative():
    p_zero = ComplianceSecurityPolicy(max_catalog_mappings=0)
    with pytest.raises(ValueError, match=COMPLIANCEPOL_ERR_VALIDATION):
        p_zero.validate()

    p_over = ComplianceSecurityPolicy(max_catalog_mappings=5000)
    with pytest.raises(ValueError, match=COMPLIANCEPOL_ERR_VALIDATION):
        p_over.validate()

    p_pct_neg = ComplianceSecurityPolicy(min_compliant_percentage=-5.0)
    with pytest.raises(ValueError, match=COMPLIANCEPOL_ERR_VALIDATION):
        p_pct_neg.validate()

    p_pct_over = ComplianceSecurityPolicy(min_compliant_percentage=100.5)
    with pytest.raises(ValueError, match=COMPLIANCEPOL_ERR_VALIDATION):
        p_pct_over.validate()


def test_registration_evaluation_happy_path():
    policy = ComplianceSecurityPolicy()
    entry = _make_entry(status="compliant", mitigation="PEP gate enforced and verified")
    verdict = policy.evaluate_registration(entry)
    assert verdict.verdict == "permit"


def test_registration_missing_threat_ids():
    policy = ComplianceSecurityPolicy()
    entry = _make_entry(threat_ids=[])
    verdict = policy.evaluate_registration(entry)
    assert verdict.verdict == "deny"
    assert verdict.code == COMPLIANCEPOL_ERR_THREAT_REQUIRED


def test_registration_compliant_without_mitigation():
    policy = ComplianceSecurityPolicy()
    entry = _make_entry(status="compliant", mitigation="")
    verdict = policy.evaluate_registration(entry)
    assert verdict.verdict == "deny"
    assert verdict.code == COMPLIANCEPOL_ERR_MITIGATION_REQUIRED


def test_registration_framework_whitelist():
    policy = ComplianceSecurityPolicy(permitted_frameworks=["soc2_type2"])
    entry_nist = _make_entry(framework="nist_sp_800_53_rev5")
    verdict = policy.evaluate_registration(entry_nist)
    assert verdict.verdict == "deny"
    assert verdict.code == COMPLIANCEPOL_ERR_FRAMEWORK_PROHIBITED

    entry_soc2 = _make_entry(framework="soc2_type2")
    verdict_soc2 = policy.evaluate_registration(entry_soc2)
    assert verdict_soc2.verdict == "permit"


def test_permissive_and_disabled_modes():
    perm_policy = ComplianceSecurityPolicy.permissive()
    entry_bad = _make_entry(threat_ids=[])
    verdict_perm = perm_policy.evaluate_registration(entry_bad)
    assert verdict_perm.verdict == "permit_with_warning"
    assert "requires at least one linked threat" in verdict_perm.warning

    dis_policy = ComplianceSecurityPolicy.disabled()
    verdict_dis = dis_policy.evaluate_registration(entry_bad)
    assert verdict_dis.verdict == "permit"


def test_status_transition_evaluation():
    policy = ComplianceSecurityPolicy()
    entry = _make_entry(status="non_compliant")

    # To compliant with empty mitigation -> Deny
    v_empty = policy.evaluate_status_transition(entry.id, "compliant", "")
    assert v_empty.verdict == "deny"
    assert v_empty.code == COMPLIANCEPOL_ERR_MITIGATION_REQUIRED

    # To compliant with valid mitigation -> Permit
    v_valid = policy.evaluate_status_transition(entry.id, "compliant", "Cryptographic checks pass")
    assert v_valid.verdict == "permit"

    # To non_compliant -> Permit
    v_non = policy.evaluate_status_transition(entry.id, "non_compliant", "")
    assert v_non.verdict == "permit"


def test_assessment_evaluation():
    policy = ComplianceSecurityPolicy(min_compliant_percentage=80.0)

    passing_rep = ComplianceAssessmentReport(
        total_mappings=10,
        compliant_count=9,
        partially_compliant_count=0,
        non_compliant_count=1,
        not_applicable_count=0,
        compliance_percentage=90.0,
        gap_control_ids=["AC-2"],
        evaluated_at="2026-10-11T00:00:00Z",
    )
    assert policy.evaluate_assessment(passing_rep).verdict == "permit"

    failing_rep = ComplianceAssessmentReport(
        total_mappings=10,
        compliant_count=6,
        partially_compliant_count=2,
        non_compliant_count=2,
        not_applicable_count=0,
        compliance_percentage=60.0,
        gap_control_ids=["AC-2", "AC-3"],
        evaluated_at="2026-10-11T00:00:00Z",
    )
    v_fail = policy.evaluate_assessment(failing_rep)
    assert v_fail.verdict == "deny"
    assert v_fail.code == COMPLIANCEPOL_ERR_THRESHOLD_UNMET


def test_capacity_and_override_evaluation():
    policy = ComplianceSecurityPolicy(max_catalog_mappings=100, allow_canonical_override=False)

    # Capacity under
    assert policy.evaluate_capacity(50).verdict == "permit"
    # Capacity reached
    v_cap = policy.evaluate_capacity(100)
    assert v_cap.verdict == "deny"
    assert v_cap.code == COMPLIANCEPOL_ERR_CAPACITY_EXCEEDED

    # Override forbidden
    v_over = policy.evaluate_override("admin")
    assert v_over.verdict == "deny"
    assert v_over.code == COMPLIANCEPOL_ERR_OVERRIDE_FORBIDDEN

    # Override permitted when enabled
    p_allowed = ComplianceSecurityPolicy(allow_canonical_override=True)
    assert p_allowed.evaluate_override("admin").verdict == "permit"


def test_file_persistence_roundtrip():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        path = Path(tmpdir) / "compliance_policy.json"
        policy = ComplianceSecurityPolicy(
            permitted_frameworks=["soc2_type2", "iso_27001_2022"],
            min_compliant_percentage=85.0,
        )
        policy.save_to_path(path)

        loaded = ComplianceSecurityPolicy.load_from_path(path)
        assert loaded.permitted_frameworks == ["soc2_type2", "iso_27001_2022"]
        assert loaded.min_compliant_percentage == 85.0
        assert loaded.mode == CompliancePolicyMode.ENFORCING
