"""AIOS Compliance Mapping — MCP/API surface (Component 7) — T-02895 SCAFFOLD.

Contract: docs/tasks/evidence/T-02894-spec.md (normative).
Prior art: docs/tasks/evidence/T-02893-research.md.

Typed interfaces only; every function body raises NotImplementedError until
T-02896 (Implementation). Constants and dataclass shapes are transcribed from
code/aiosh-rust/aiosh-core/src/compliance_data_model.rs (binding parity, spec §6).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

# --- Tool surface (spec §2) -------------------------------------------------

TOOL_NAME = "aios.compliance"
ACTIONS = ("list", "show", "register", "status", "assess", "check-pep", "init")
READ_ACTIONS = ("list", "show", "assess", "check-pep")
WRITE_ACTIONS = ("register", "status", "init")

# --- Constants (parity with compliance_data_model.rs) -----------------------

MAX_COMPLIANCE_ID_LEN = 64
MAX_COMPLIANCE_TITLE_LEN = 128
MAX_COMPLIANCE_DESC_LEN = 2048
MAX_COMPLIANCE_NOTES_LEN = 2048
MAX_THREAT_IDS_COUNT = 16
MAX_TAGS_COUNT = 16
MAX_COMPLIANCE_ENTRIES_CAPACITY = 1024

# Error codes (identical strings cross-substrate — spec §4)
PARAM_INVALID = "PARAM_INVALID"
NOT_FOUND = "NOT_FOUND"
STORE_UNAVAILABLE = "STORE_UNAVAILABLE"
STORE_EXISTS = "STORE_EXISTS"
COMPLIANCE_ERR_INVALID_ID = "COMPLIANCE_ERR_INVALID_ID"
COMPLIANCE_ERR_INVALID_TITLE = "COMPLIANCE_ERR_INVALID_TITLE"
COMPLIANCE_ERR_BOUNDS_EXCEEDED = "COMPLIANCE_ERR_BOUNDS_EXCEEDED"
COMPLIANCE_ERR_CONTROL_CHARS = "COMPLIANCE_ERR_CONTROL_CHARS"
COMPLIANCE_ERR_DUPLICATE_ID = "COMPLIANCE_ERR_DUPLICATE_ID"
COMPLIANCE_ERR_INVALID_STATUS_TRANSITION = "COMPLIANCE_ERR_INVALID_STATUS_TRANSITION"
COMPLIANCE_ERR_MISSING_SUBSTRATE_REF = "COMPLIANCE_ERR_MISSING_SUBSTRATE_REF"
COMPLIANCESVC_ERR_PATH_TRAVERSAL = "COMPLIANCESVC_ERR_PATH_TRAVERSAL"

# Closed vocabularies (spec §2 / §6)
FRAMEWORKS = (
    "nist_sp_800_53_rev5", "soc2_type2", "iso_27001_2022",
    "cis_controls_v8", "hipaa_security", "pci_dss_v4",
)
FRAMEWORK_ALIASES = {
    "nist_sp_800_53_rev5": "nist_sp_800_53_rev5", "nist": "nist_sp_800_53_rev5",
    "nist_800_53": "nist_sp_800_53_rev5",
    "soc2_type2": "soc2_type2", "soc2": "soc2_type2", "soc_2": "soc2_type2",
    "iso_27001_2022": "iso_27001_2022", "iso27001": "iso_27001_2022",
    "iso": "iso_27001_2022",
    "cis_controls_v8": "cis_controls_v8", "cis": "cis_controls_v8",
    "cis_v8": "cis_controls_v8",
    "hipaa_security": "hipaa_security", "hipaa": "hipaa_security",
    "pci_dss_v4": "pci_dss_v4", "pci": "pci_dss_v4", "pci_dss": "pci_dss_v4",
}
STATUSES = ("compliant", "partially_compliant", "non_compliant", "not_applicable")
STATUS_ALIASES = {
    "compliant": "compliant",
    "partially_compliant": "partially_compliant", "partial": "partially_compliant",
    "non_compliant": "non_compliant", "noncompliant": "non_compliant",
    "not_applicable": "not_applicable", "na": "not_applicable",
}
# NOTE (parity caveat): compliance_data_model.rs can_transition_to() ends with a
# `_ => true` fallback, which makes every transition legal today. Transcribed
# faithfully (spec §6: the Rust state machine is authoritative); the explicit
# arms are enumerated below and the fallback keeps parity.
STATUS_TRANSITIONS = {
    "non_compliant": ("partially_compliant", "compliant", "not_applicable"),
    "partially_compliant": ("compliant", "non_compliant"),
    "compliant": ("partially_compliant", "non_compliant"),
    "not_applicable": ("non_compliant", "compliant"),
}

TARGET_TYPES = (
    "pep_gate", "capability_token", "audit_ring", "threat_mitigation",
    "constitution_rule",
)


# --- Data shapes (field order == Rust struct order; byte-stable round-trip) --

@dataclass
class ComplianceMappingEntry:
    # All fields carry defaults so the declaration order can match the Rust
    # struct exactly (byte-stable round-trip, spec §5).
    id: str = ""
    control_id: str = ""
    framework: str = ""
    target_type: str = ""
    target_ref: str = ""
    threat_ids: list[str] = field(default_factory=list)
    status: str = ""
    mitigation_summary: str = ""
    tags: list[str] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""


@dataclass
class ComplianceCatalogSnapshot:
    mappings: list[ComplianceMappingEntry] = field(default_factory=list)


@dataclass
class ComplianceAssessmentReport:
    framework: Optional[str]
    total: int
    by_status: dict[str, int] = field(default_factory=dict)
    by_framework: dict[str, int] = field(default_factory=dict)
    entries: list[ComplianceMappingEntry] = field(default_factory=list)


# --- Interfaces (bodies fail loudly until T-02896) --------------------------

def _todo(name: str) -> NotImplementedError:
    return NotImplementedError(
        f"T-02896 IMPLEMENTATION: {name} is scaffold-only (T-02895)")


def validate_identifier(value: str, label: str) -> str:
    """Validate an identifier per compliance_data_model.rs. Returns value."""
    raise _todo("validate_identifier")


def validate_title(value: str, label: str) -> str:
    raise _todo("validate_title")


def validate_text_length(value: str, max_len: int, label: str) -> str:
    raise _todo("validate_text_length")


def parse_framework(value: str) -> str:
    """Canonicalize a framework alias (FRAMEWORK_ALIASES). Raises PARAM_INVALID."""
    raise _todo("parse_framework")


def parse_status(value: str) -> str:
    """Canonicalize a status alias (STATUS_ALIASES). Raises PARAM_INVALID."""
    raise _todo("parse_status")


def validate_path(path: str) -> str:
    """Path hygiene (CWE-22/CWE-59): .json extension, no traversal. Returns path."""
    raise _todo("validate_path")


def load_store(path: str) -> ComplianceCatalogSnapshot:
    """Load the canonical store (spec §5). Raises STORE_UNAVAILABLE."""
    raise _todo("load_store")


def save_store(path: str, snapshot: ComplianceCatalogSnapshot) -> None:
    """Atomic byte-stable write (spec §5): preserve key order, .tmp + os.replace."""
    raise _todo("save_store")


def init_store(path: str) -> ComplianceCatalogSnapshot:
    """Create the store with the canonical baseline. Raises STORE_EXISTS."""
    raise _todo("init_store")


def list_mappings(snapshot: ComplianceCatalogSnapshot,
                  framework: str | None = None,
                  status: str | None = None) -> list[ComplianceMappingEntry]:
    raise _todo("list_mappings")


def get_mapping(snapshot: ComplianceCatalogSnapshot, id: str) -> ComplianceMappingEntry:
    """Raises NOT_FOUND."""
    raise _todo("get_mapping")


def register_mapping(snapshot: ComplianceCatalogSnapshot, **fields: Any) -> ComplianceCatalogSnapshot:
    """Insert a validated entry. Raises DUPLICATE_ID / BOUNDS / INVALID_*."""
    raise _todo("register_mapping")


def update_status(snapshot: ComplianceCatalogSnapshot, id: str,
                  status: str, reason: str | None = None) -> ComplianceCatalogSnapshot:
    """Status transition per can_transition_to. Raises INVALID_STATUS_TRANSITION."""
    raise _todo("update_status")


def assess_framework(snapshot: ComplianceCatalogSnapshot,
                     framework: str | None = None) -> ComplianceAssessmentReport:
    raise _todo("assess_framework")


def verify_pep_coverage(snapshot: ComplianceCatalogSnapshot, gate_id: str) -> bool:
    raise _todo("verify_pep_coverage")


def uncovered_pep_gates(snapshot: ComplianceCatalogSnapshot,
                        required_gates: list[str]) -> list[str]:
    raise _todo("uncovered_pep_gates")


def execute(action: str, **kwargs: Any) -> dict:
    """Tool-facing dispatcher (spec §2): validate -> operate -> envelope.

    Returns the spec §3 envelope on success; raises ValueError('CODE: msg')
    on failure (the tool wrapper maps these to the spec §4 error envelope)."""
    raise _todo("execute")
