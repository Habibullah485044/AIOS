"""Compliance Mapping Security Policy Subsystem (COMPLIANCEPOL1..COMPLIANCEPOL7).

Provides declarative governance over compliance mapping registration,
lifecycle status transitions, framework enforcement, and assessment thresholds.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from aiosh_mcp.compliance import (
    FRAMEWORKS,
    STATUSES,
    ComplianceMappingEntry,
    ComplianceAssessmentReport,
)

COMPLIANCEPOL_ERR_VALIDATION = "COMPLIANCEPOL_ERR_VALIDATION"
COMPLIANCEPOL_ERR_DENIED = "COMPLIANCEPOL_ERR_DENIED"
COMPLIANCEPOL_ERR_THREAT_REQUIRED = "COMPLIANCEPOL_ERR_THREAT_REQUIRED"
COMPLIANCEPOL_ERR_MITIGATION_REQUIRED = "COMPLIANCEPOL_ERR_MITIGATION_REQUIRED"
COMPLIANCEPOL_ERR_FRAMEWORK_PROHIBITED = "COMPLIANCEPOL_ERR_FRAMEWORK_PROHIBITED"
COMPLIANCEPOL_ERR_THRESHOLD_UNMET = "COMPLIANCEPOL_ERR_THRESHOLD_UNMET"
COMPLIANCEPOL_ERR_CAPACITY_EXCEEDED = "COMPLIANCEPOL_ERR_CAPACITY_EXCEEDED"
COMPLIANCEPOL_ERR_OVERRIDE_FORBIDDEN = "COMPLIANCEPOL_ERR_OVERRIDE_FORBIDDEN"
COMPLIANCEPOL_ERR_IO = "COMPLIANCEPOL_ERR_IO"
COMPLIANCEPOL_ERR_PARSE = "COMPLIANCEPOL_ERR_PARSE"

MAX_COMPLIANCE_SECURITY_POLICY_BYTES = 65_536  # 64 KiB


class CompliancePolicyMode(str, Enum):
    ENFORCING = "enforcing"
    PERMISSIVE = "permissive"
    DISABLED = "disabled"


@dataclass
class CompliancePolicyVerdict:
    verdict: str  # "permit", "permit_with_warning", "deny"
    warning: Optional[str] = None
    reason: Optional[str] = None
    code: Optional[str] = None

    @classmethod
    def permit(cls) -> "CompliancePolicyVerdict":
        return cls(verdict="permit")

    @classmethod
    def permit_with_warning(cls, warning: str) -> "CompliancePolicyVerdict":
        return cls(verdict="permit_with_warning", warning=warning)

    @classmethod
    def deny(cls, reason: str, code: str) -> "CompliancePolicyVerdict":
        return cls(verdict="deny", reason=reason, code=code)


@dataclass
class ComplianceSecurityPolicy:
    version: str = "1.0.0"
    mode: CompliancePolicyMode = CompliancePolicyMode.ENFORCING
    require_threat_linkage: bool = True
    require_mitigation_on_compliant: bool = True
    permitted_frameworks: List[str] = field(default_factory=list)
    min_compliant_percentage: float = 80.0
    max_catalog_mappings: int = 1024
    allow_canonical_override: bool = False

    def validate(self) -> None:
        if not self.version.strip() or not self.version.startswith("1."):
            raise ValueError(f"{COMPLIANCEPOL_ERR_VALIDATION}: version must begin with '1.'")
        if len(self.version) > 32:
            raise ValueError(f"{COMPLIANCEPOL_ERR_VALIDATION}: version length exceeds maximum 32")
        if len(self.permitted_frameworks) > 16:
            raise ValueError(f"{COMPLIANCEPOL_ERR_VALIDATION}: permitted_frameworks count exceeds maximum 16")
        if self.max_catalog_mappings <= 0 or self.max_catalog_mappings > 4096:
            raise ValueError(f"{COMPLIANCEPOL_ERR_VALIDATION}: max_catalog_mappings out of bounds [1, 4096]")
        if self.min_compliant_percentage < 0.0 or self.min_compliant_percentage > 100.0:
            raise ValueError(f"{COMPLIANCEPOL_ERR_VALIDATION}: min_compliant_percentage out of bounds [0.0, 100.0]")

    def evaluate_registration(self, entry: ComplianceMappingEntry) -> CompliancePolicyVerdict:
        if self.mode == CompliancePolicyMode.DISABLED:
            return CompliancePolicyVerdict.permit()

        # Framework whitelist
        if self.permitted_frameworks:
            fw_val = entry.framework.value if hasattr(entry.framework, "value") else str(entry.framework)
            if fw_val not in self.permitted_frameworks:
                reason = f"Framework '{fw_val}' is not permitted by security policy"
                if self.mode == CompliancePolicyMode.ENFORCING:
                    return CompliancePolicyVerdict.deny(reason, COMPLIANCEPOL_ERR_FRAMEWORK_PROHIBITED)
                return CompliancePolicyVerdict.permit_with_warning(reason)

        # Threat linkage
        if self.require_threat_linkage and not entry.threat_ids:
            reason = f"Compliance entry '{entry.id}' requires at least one linked threat ID"
            if self.mode == CompliancePolicyMode.ENFORCING:
                return CompliancePolicyVerdict.deny(reason, COMPLIANCEPOL_ERR_THREAT_REQUIRED)
            return CompliancePolicyVerdict.permit_with_warning(reason)

        # Compliant status mitigation
        status_val = entry.status.value if hasattr(entry.status, "value") else str(entry.status)
        if self.require_mitigation_on_compliant and status_val == "compliant":
            mitigation = (entry.mitigation_summary or "").strip()
            if len(mitigation) < 3:
                reason = f"Entry '{entry.id}' cannot be marked Compliant without mitigation rationale"
                if self.mode == CompliancePolicyMode.ENFORCING:
                    return CompliancePolicyVerdict.deny(reason, COMPLIANCEPOL_ERR_MITIGATION_REQUIRED)
                return CompliancePolicyVerdict.permit_with_warning(reason)

        return CompliancePolicyVerdict.permit()

    def evaluate_status_transition(
        self,
        entry_id: str,
        new_status: str,
        reason_or_mitigation: str,
    ) -> CompliancePolicyVerdict:
        if self.mode == CompliancePolicyMode.DISABLED:
            return CompliancePolicyVerdict.permit()

        norm_status = new_status.lower()
        if self.require_mitigation_on_compliant and norm_status == "compliant":
            if len(reason_or_mitigation.strip()) < 3:
                reason = f"Transitioning '{entry_id}' to Compliant requires documented mitigation summary (minimum 3 chars)"
                if self.mode == CompliancePolicyMode.ENFORCING:
                    return CompliancePolicyVerdict.deny(reason, COMPLIANCEPOL_ERR_MITIGATION_REQUIRED)
                return CompliancePolicyVerdict.permit_with_warning(reason)

        return CompliancePolicyVerdict.permit()

    def evaluate_assessment(self, assessment: ComplianceAssessmentReport) -> CompliancePolicyVerdict:
        if self.mode == CompliancePolicyMode.DISABLED:
            return CompliancePolicyVerdict.permit()

        if assessment.compliance_percentage < self.min_compliant_percentage:
            reason = f"Assessment compliance percentage {assessment.compliance_percentage:.1f}% falls below policy threshold {self.min_compliant_percentage:.1f}%"
            if self.mode == CompliancePolicyMode.ENFORCING:
                return CompliancePolicyVerdict.deny(reason, COMPLIANCEPOL_ERR_THRESHOLD_UNMET)
            return CompliancePolicyVerdict.permit_with_warning(reason)

        return CompliancePolicyVerdict.permit()

    @classmethod
    def permissive(cls) -> "ComplianceSecurityPolicy":
        return cls(mode=CompliancePolicyMode.PERMISSIVE)

    @classmethod
    def disabled(cls) -> "ComplianceSecurityPolicy":
        return cls(mode=CompliancePolicyMode.DISABLED)

    def evaluate_capacity(self, current_count: int) -> CompliancePolicyVerdict:
        if self.mode == CompliancePolicyMode.DISABLED:
            return CompliancePolicyVerdict.permit()

        if current_count >= self.max_catalog_mappings:
            reason = f"Compliance catalog entry count {current_count} reaches policy maximum {self.max_catalog_mappings}"
            if self.mode == CompliancePolicyMode.ENFORCING:
                return CompliancePolicyVerdict.deny(reason, COMPLIANCEPOL_ERR_CAPACITY_EXCEEDED)
            return CompliancePolicyVerdict.permit_with_warning(reason)

        return CompliancePolicyVerdict.permit()

    def evaluate_override(self, _caller: str) -> CompliancePolicyVerdict:
        if self.mode == CompliancePolicyMode.DISABLED:
            return CompliancePolicyVerdict.permit()

        if not self.allow_canonical_override:
            reason = "Canonical compliance override forbidden by security policy"
            if self.mode == CompliancePolicyMode.ENFORCING:
                return CompliancePolicyVerdict.deny(reason, COMPLIANCEPOL_ERR_OVERRIDE_FORBIDDEN)
            return CompliancePolicyVerdict.permit_with_warning(reason)

        return CompliancePolicyVerdict.permit()

    @classmethod
    def load_from_path(cls, path: str | Path) -> "ComplianceSecurityPolicy":
        return cls.load_from_file(path)

    @classmethod
    def load_from_file(cls, path: str | Path) -> "ComplianceSecurityPolicy":
        p = Path(path)
        if p.is_symlink():
            raise ValueError(f"{COMPLIANCEPOL_ERR_IO}: symlinks rejected for security policy")
        if p.stat().st_size > MAX_COMPLIANCE_SECURITY_POLICY_BYTES:
            raise ValueError(f"{COMPLIANCEPOL_ERR_IO}: policy file exceeds {MAX_COMPLIANCE_SECURITY_POLICY_BYTES} bytes")
        with open(p, "rb") as f:
            raw = f.read(MAX_COMPLIANCE_SECURITY_POLICY_BYTES + 1)
        if len(raw) > MAX_COMPLIANCE_SECURITY_POLICY_BYTES:
            raise ValueError(f"{COMPLIANCEPOL_ERR_IO}: policy file exceeds {MAX_COMPLIANCE_SECURITY_POLICY_BYTES} bytes")
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError(f"{COMPLIANCEPOL_ERR_PARSE}: invalid policy JSON: {exc}") from exc
        mode = CompliancePolicyMode(data.get("mode", "enforcing"))
        policy = cls(
            version=data.get("version", "1.0.0"),
            mode=mode,
            require_threat_linkage=data.get("require_threat_linkage", True),
            require_mitigation_on_compliant=data.get("require_mitigation_on_compliant", True),
            permitted_frameworks=data.get("permitted_frameworks", []),
            min_compliant_percentage=float(data.get("min_compliant_percentage", 80.0)),
            max_catalog_mappings=int(data.get("max_catalog_mappings", 1024)),
            allow_canonical_override=bool(data.get("allow_canonical_override", False)),
        )
        policy.validate()
        return policy

    def save_to_file(self, path: str | Path) -> None:
        self.validate()
        p = Path(path)
        data = {
            "version": self.version,
            "mode": self.mode.value,
            "require_threat_linkage": self.require_threat_linkage,
            "require_mitigation_on_compliant": self.require_mitigation_on_compliant,
            "permitted_frameworks": self.permitted_frameworks,
            "min_compliant_percentage": self.min_compliant_percentage,
            "max_catalog_mappings": self.max_catalog_mappings,
            "allow_canonical_override": self.allow_canonical_override,
        }
        encoded = json.dumps(data, indent=2)
        if len(encoded.encode("utf-8")) > MAX_COMPLIANCE_SECURITY_POLICY_BYTES:
            raise ValueError(f"{COMPLIANCEPOL_ERR_IO}: serialized policy exceeds cap")
        tmp = p.with_suffix(f".tmp.{os.getpid()}")
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(encoded)
            tmp.replace(p)
        finally:
            if tmp.exists():
                try:
                    tmp.unlink()
                except OSError:
                    pass

    def save_to_path(self, path: str | Path) -> None:
        self.save_to_file(path)
