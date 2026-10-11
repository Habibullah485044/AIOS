"""Automated Test Suite for Compliance Mapping — MCP Substrate (T-02916 Implementation).

Contract: docs/tasks/evidence/T-02914-spec.md.
Implements automated vectors AUTOCOMPLIANCE1..AUTOCOMPLIANCE10.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from aiosh_mcp import compliance
from aiosh_mcp import compliance_config


def test_autocompliance1_lifecycle_and_transitions():
    """AUTOCOMPLIANCE1: Full Compliance Lifecycle & Status Transitions."""
    snap = compliance.ComplianceCatalogSnapshot()
    entry = compliance.build_entry(
        id="ac1-control",
        control_id="AC-1",
        framework="nist_sp_800_53_rev5",
        target_type="pep_gate",
        target_ref="pep.auth.check",
        status="non_compliant",
        mitigation_summary="",
    )
    compliance.register_mapping(snap, entry)
    assert len(snap.mappings) == 1
    assert snap.mappings[0].status == "non_compliant"

    # Transition: non_compliant -> partially_compliant
    updated = compliance.update_status(snap, "ac1-control", "partially_compliant", reason="Partial rollout")
    assert updated.status == "partially_compliant"

    # Negative: transition to compliant without summary or reason fails closed
    with pytest.raises(ValueError) as exc:
        compliance.update_status(snap, "ac1-control", "compliant", reason="")
    assert compliance.COMPLIANCE_ERR_BOUNDS_EXCEEDED in str(exc.value)

    # Valid transition to compliant with non-empty reason
    updated = compliance.update_status(snap, "ac1-control", "compliant", reason="Rollout fully verified")
    assert updated.status == "compliant"


def test_autocompliance2_duplicate_rejection():
    """AUTOCOMPLIANCE2: Duplicate Control & Collision Rejection."""
    snap = compliance.ComplianceCatalogSnapshot()
    e1 = compliance.build_entry(
        id="dup-check-01",
        control_id="AC-2",
        framework="soc2_type2",
        target_type="pep_gate",
        target_ref="pep.grant.verify",
        status="compliant",
        mitigation_summary="Verified via cryptographic check",
    )
    compliance.register_mapping(snap, e1)
    assert len(snap.mappings) == 1

    # Attempt to register duplicate ID
    e2 = compliance.build_entry(
        id="dup-check-01",
        control_id="AC-2-dup",
        framework="soc2_type2",
        target_type="pep_gate",
        target_ref="pep.grant.verify",
        status="compliant",
        mitigation_summary="Duplicate attempt",
    )
    with pytest.raises(ValueError) as exc:
        compliance.register_mapping(snap, e2)
    assert compliance.COMPLIANCE_ERR_DUPLICATE_ID in str(exc.value)
    assert len(snap.mappings) == 1


def test_autocompliance3_bounds_validation():
    """AUTOCOMPLIANCE3: Identifier, Text & Array Bounds Validation."""
    # 1. Identifier max length exceeded (> 64)
    with pytest.raises(ValueError) as exc:
        compliance.validate_identifier("A" * 65, "id")
    assert compliance.COMPLIANCE_ERR_BOUNDS_EXCEEDED in str(exc.value)

    # 2. Identifier invalid characters
    with pytest.raises(ValueError) as exc:
        compliance.validate_identifier("invalid id with spaces!", "id")
    assert compliance.COMPLIANCE_ERR_INVALID_ID in str(exc.value)

    # 3. Title max length exceeded (> 128)
    with pytest.raises(ValueError) as exc:
        compliance.validate_title("T" * 129, "title")
    assert compliance.COMPLIANCE_ERR_BOUNDS_EXCEEDED in str(exc.value)

    # 4. Title control character
    with pytest.raises(ValueError) as exc:
        compliance.validate_title("Title with \x00 null byte", "title")
    assert compliance.COMPLIANCE_ERR_CONTROL_CHARS in str(exc.value)


def test_autocompliance4_precedence_ladder(monkeypatch, tmp_path):
    """AUTOCOMPLIANCE4: 4-Level Precedence Ladder Resolution."""
    # Level 4 default
    monkeypatch.delenv(compliance_config.ENV_COMPLIANCE_CONFIG, raising=False)
    monkeypatch.delenv(compliance_config.ENV_COMPLIANCE_MAP_PATH, raising=False)
    resolved = compliance_config.resolve(arg_config="nonexistent_config_file.json")
    assert resolved["source"]["store_path"] == "default"
    assert resolved["config"]["store_path"] == compliance.DEFAULT_STORE_PATH

    # Level 3 config file
    cfg_file = tmp_path / "custom_compliance_config.json"
    cfg_file.write_text(json.dumps({
        "version": "1.0.0",
        "store_path": "configured_path.json",
        "max_entries": 500,
    }), encoding="utf-8")

    resolved_cfg = compliance_config.resolve(arg_config=str(cfg_file))
    assert resolved_cfg["source"]["store_path"] == "file"
    assert resolved_cfg["config"]["store_path"] == "configured_path.json"
    assert resolved_cfg["config"]["max_entries"] == 500

    # Level 2 env var
    monkeypatch.setenv(compliance_config.ENV_COMPLIANCE_MAP_PATH, "env_store_path.json")
    resolved_env = compliance_config.resolve(arg_config=str(cfg_file))
    assert resolved_env["source"]["store_path"] == "env"
    assert resolved_env["config"]["store_path"] == "env_store_path.json"

    # Level 1 explicit argument
    resolved_arg = compliance_config.resolve(arg_path="arg_store_path.json", arg_config=str(cfg_file))
    assert resolved_arg["source"]["store_path"] == "argument"
    assert resolved_arg["config"]["store_path"] == "arg_store_path.json"


def test_autocompliance5_hygiene_predicate():
    """AUTOCOMPLIANCE5: CWE-15 / CWE-22 Hygiene Predicate Defense."""
    assert compliance_config.hygiene_ok("valid_file.json") is True
    assert compliance_config.hygiene_ok("subdir/nested.json") is True

    # Traversal rejected
    assert compliance_config.hygiene_ok("../escape.json") is False
    assert compliance_config.hygiene_ok("dir/../../secret.json") is False

    # Control chars rejected
    assert compliance_config.hygiene_ok("file\x00name.json") is False
    assert compliance_config.hygiene_ok("bad\npath.json") is False

    # Length cap rejected
    assert compliance_config.hygiene_ok("a" * (compliance_config.MAX_CONFIG_PATH_LEN + 1)) is False

    # Empty rejected
    assert compliance_config.hygiene_ok("") is False
    assert compliance_config.hygiene_ok("   ") is False


def test_autocompliance6_size_caps(tmp_path):
    """AUTOCOMPLIANCE6: Pre-Parse File Size Bounds & CWE-400 DoS Defense."""
    assert compliance_config.MAX_CONFIG_FILE_BYTES == 64 * 1024

    # File > 64 KiB
    oversized = tmp_path / "oversized_config.json"
    oversized.write_text("x" * (65 * 1024), encoding="utf-8")

    with pytest.raises(ValueError) as exc:
        compliance_config.load_config(str(oversized))
    assert compliance_config.COMPLIANCECONF_ERR_FILE_SIZE in str(exc.value)


def test_autocompliance7_audit_immutability():
    """AUTOCOMPLIANCE7: Audit Immutability & Audit Logging Guarantee."""
    default_cfg = compliance_config.default_config()
    assert default_cfg["audit_all_mutations"] is True

    # Explicit attempt to disable mutation auditing clamped to True
    validated = compliance_config.validate({"audit_all_mutations": False})
    assert validated["audit_all_mutations"] is True


def test_autocompliance8_pep_gating():
    """AUTOCOMPLIANCE8: Proof of Restraint & PEP Gating (Invariant I-2)."""
    snap = compliance.ComplianceCatalogSnapshot()
    entry = compliance.build_entry(
        id="pep-gate-01",
        control_id="SC-7",
        framework="nist_sp_800_53_rev5",
        target_type="pep_gate",
        target_ref="pep.exec.tool",
        status="compliant",
        mitigation_summary="PEP gating validated",
    )
    compliance.register_mapping(snap, entry)

    assert compliance.verify_pep_coverage(snap, "pep.exec.tool") is True
    assert compliance.verify_pep_coverage(snap, "pep.unmapped.action") is False

    uncovered = compliance.uncovered_pep_gates(snap, ["pep.exec.tool", "pep.unmapped.action"])
    assert uncovered == ["pep.unmapped.action"]


def test_autocompliance9_assessment_scoring():
    """AUTOCOMPLIANCE9: Assessment Scoring & Statistics Consistency."""
    snap = compliance.ComplianceCatalogSnapshot()
    snap.mappings.append(compliance.build_entry(
        id="ctrl-01", control_id="AC-1", framework="nist_sp_800_53_rev5",
        target_type="pep_gate", target_ref="pep.1", status="compliant",
        mitigation_summary="Fully compliant control"
    ))
    snap.mappings.append(compliance.build_entry(
        id="ctrl-02", control_id="AC-2", framework="nist_sp_800_53_rev5",
        target_type="pep_gate", target_ref="pep.2", status="partially_compliant"
    ))
    snap.mappings.append(compliance.build_entry(
        id="ctrl-03", control_id="AC-3", framework="nist_sp_800_53_rev5",
        target_type="pep_gate", target_ref="pep.3", status="non_compliant"
    ))
    snap.mappings.append(compliance.build_entry(
        id="ctrl-04", control_id="AC-4", framework="nist_sp_800_53_rev5",
        target_type="pep_gate", target_ref="pep.4", status="not_applicable"
    ))

    report = compliance.assess_framework(snap, framework="nist_sp_800_53_rev5")
    assert report.total_mappings == 4
    assert report.compliant_count == 1
    assert report.partially_compliant_count == 1
    assert report.non_compliant_count == 1
    assert report.not_applicable_count == 1
    # 1 compliant out of 4 total = 25.0%
    assert report.compliance_percentage == 25.0
    assert set(report.gap_control_ids) == {"AC-2", "AC-3"}


def test_autocompliance10_atomic_persistence(tmp_path):
    """AUTOCOMPLIANCE10: Concurrency Safety & Atomic Persistence."""
    store_file = tmp_path / "compliance_map.json"
    snap = compliance.ComplianceCatalogSnapshot()
    snap.mappings.append(compliance.build_entry(
        id="persist-01", control_id="AU-1", framework="soc2_type2",
        target_type="audit_ring", target_ref="audit.ring.main", status="compliant",
        mitigation_summary="Audit ring operational"
    ))

    # Save
    compliance.save_store(str(store_file), snap)
    assert store_file.exists()

    # Load & round-trip check
    loaded = compliance.load_store(str(store_file))
    assert len(loaded.mappings) == 1
    assert loaded.mappings[0].id == "persist-01"

    # Security: Traversal paths rejected by validate_path
    with pytest.raises(ValueError) as exc:
        compliance.validate_path("../escape.json")
    assert compliance.COMPLIANCESVC_ERR_PATH_TRAVERSAL in str(exc.value)
