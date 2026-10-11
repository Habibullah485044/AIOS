"""AIOS Compliance Mapping — MCP/API surface (Component 7).

Contract: docs/tasks/evidence/T-02894-spec.md (normative).
Prior art: docs/tasks/evidence/T-02893-research.md.

Every function mirrors the Rust substrate semantics 1:1 (T-02893 decision D8,
"binding parity"): constants, error-code strings, validation rules, report
shape, and store serialization all match
code/aiosh-rust/aiosh-core/src/compliance_{data_model,service}.rs.
Errors are raised as ValueError('CODE: message') and mapped by the tool
wrapper into the spec §4 error envelope.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from .audit_client import utcnow_iso

# --- Tool surface (spec §2) -------------------------------------------------

TOOL_NAME = "aios.compliance"
ACTIONS = ("list", "show", "register", "status", "assess", "check-pep", "init", "stats")
READ_ACTIONS = ("list", "show", "assess", "check-pep", "stats")
WRITE_ACTIONS = ("register", "status", "init")

# --- Constants (parity with compliance_data_model.rs) -----------------------

DEFAULT_STORE_PATH = "docs/compliance_map.json"
MAX_COMPLIANCE_STORE_SIZE = 1024 * 1024  # 1 MiB (compliance_service.rs)

MAX_COMPLIANCE_ID_LEN = 64
MAX_COMPLIANCE_TITLE_LEN = 128
MAX_COMPLIANCE_DESC_LEN = 2048
MAX_COMPLIANCE_NOTES_LEN = 2048
MAX_THREAT_IDS_COUNT = 16
MAX_TAGS_COUNT = 16
MAX_COMPLIANCE_ENTRIES_CAPACITY = 1024

# Error codes (identical strings cross-substrate — spec §4)
PARAM_INVALID = "PARAM_INVALID"
STORE_EXISTS = "STORE_EXISTS"
COMPLIANCE_ERR_INVALID_ID = "COMPLIANCE_ERR_INVALID_ID"
COMPLIANCE_ERR_INVALID_TITLE = "COMPLIANCE_ERR_INVALID_TITLE"
COMPLIANCE_ERR_BOUNDS_EXCEEDED = "COMPLIANCE_ERR_BOUNDS_EXCEEDED"
COMPLIANCE_ERR_CONTROL_CHARS = "COMPLIANCE_ERR_CONTROL_CHARS"
COMPLIANCE_ERR_DUPLICATE_ID = "COMPLIANCE_ERR_DUPLICATE_ID"
COMPLIANCE_ERR_INVALID_STATUS_TRANSITION = "COMPLIANCE_ERR_INVALID_STATUS_TRANSITION"
COMPLIANCE_ERR_MISSING_SUBSTRATE_REF = "COMPLIANCE_ERR_MISSING_SUBSTRATE_REF"
COMPLIANCESVC_ERR_NOT_FOUND = "COMPLIANCESVC_ERR_NOT_FOUND"
COMPLIANCESVC_ERR_CAPACITY_EXCEEDED = "COMPLIANCESVC_ERR_CAPACITY_EXCEEDED"
COMPLIANCESVC_ERR_FILE_SIZE = "COMPLIANCESVC_ERR_FILE_SIZE"
COMPLIANCESVC_ERR_PATH_TRAVERSAL = "COMPLIANCESVC_ERR_PATH_TRAVERSAL"
COMPLIANCESVC_ERR_IO = "COMPLIANCESVC_ERR_IO"
COMPLIANCESVC_ERR_PARSE = "COMPLIANCESVC_ERR_PARSE"

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
# NOTE (parity caveat): compliance_data_model.rs can_transition_to() enumerates
# explicit pairs then falls through `_ => true` — every transition is legal in
# the Rust substrate. STATUS_TRANSITIONS documents the enumerated arms; the
# fallback below keeps 1:1 parity.
STATUS_TRANSITIONS = {
    "non_compliant": ("partially_compliant", "compliant", "not_applicable"),
    "partially_compliant": ("compliant", "non_compliant"),
    "compliant": ("partially_compliant", "non_compliant"),
    "not_applicable": ("non_compliant", "compliant"),
}
ALL_STATUSES = set(STATUSES)

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
    # Field order == ComplianceCatalogSnapshot {version, mappings, generated_at}
    version: str = "1.0.0"
    mappings: list[ComplianceMappingEntry] = field(default_factory=list)
    generated_at: str = field(default_factory=utcnow_iso)


@dataclass
class ComplianceAssessmentReport:
    # Field order == ComplianceAssessmentReport in compliance_service.rs
    total_mappings: int = 0
    compliant_count: int = 0
    partially_compliant_count: int = 0
    non_compliant_count: int = 0
    not_applicable_count: int = 0
    compliance_percentage: float = 100.0
    gap_control_ids: list[str] = field(default_factory=list)
    evaluated_at: str = field(default_factory=utcnow_iso)


def _err(code: str, msg: str) -> ValueError:
    return ValueError(f"{code}: {msg}")


# --- Validation (identical rules to compliance_data_model.rs) ---------------

def validate_identifier(value: str, label: str) -> str:
    """Trim, non-empty, <= 64 bytes, ASCII alphanumeric / '_' '-' '.' only."""
    trimmed = (value or "").strip()
    if not trimmed:
        raise _err(COMPLIANCE_ERR_INVALID_ID, f"{label} cannot be empty")
    if len(trimmed.encode("utf-8")) > MAX_COMPLIANCE_ID_LEN:
        raise _err(COMPLIANCE_ERR_BOUNDS_EXCEEDED,
                   f"{label} exceeds maximum length {MAX_COMPLIANCE_ID_LEN}")
    if not all((c.isascii() and c.isalnum()) or c in "_-." for c in trimmed):
        raise _err(COMPLIANCE_ERR_INVALID_ID,
                   f"{label} contains invalid characters (allowed: alphanumeric, '_', '-', '.')")
    return value


def validate_title(value: str, label: str) -> str:
    trimmed = (value or "").strip()
    if not trimmed:
        raise _err(COMPLIANCE_ERR_INVALID_TITLE, f"{label} cannot be empty")
    if len(trimmed.encode("utf-8")) > MAX_COMPLIANCE_TITLE_LEN:
        raise _err(COMPLIANCE_ERR_BOUNDS_EXCEEDED,
                   f"{label} exceeds maximum length {MAX_COMPLIANCE_TITLE_LEN}")
    if any(ord(c) < 32 or ord(c) == 127 for c in trimmed):
        raise _err(COMPLIANCE_ERR_CONTROL_CHARS, f"{label} contains forbidden control characters")
    return value


def validate_text_length(value: str, max_len: int, label: str) -> str:
    """Byte-length bound (Rust str::len) + control chars except \\n \\r \\t."""
    text = value or ""
    if len(text.encode("utf-8")) > max_len:
        raise _err(COMPLIANCE_ERR_BOUNDS_EXCEEDED,
                   f"{label} exceeds maximum length {max_len}")
    if any((ord(c) < 32 or ord(c) == 127) and c not in "\n\r\t" for c in text):
        raise _err(COMPLIANCE_ERR_CONTROL_CHARS, f"{label} contains forbidden control characters")
    return value


def parse_framework(value: str) -> str:
    """Canonicalize a framework alias (FRAMEWORK_ALIASES). Raises PARAM_INVALID."""
    key = (value or "").strip().lower()
    canon = FRAMEWORK_ALIASES.get(key)
    if canon is None:
        raise _err(PARAM_INVALID,
                   f"parse_framework: unknown framework {value!r} "
                   f"(valid: {', '.join(FRAMEWORKS)})")
    return canon


def parse_status(value: str) -> str:
    """Canonicalize a status alias (STATUS_ALIASES). Raises PARAM_INVALID."""
    key = (value or "").strip().lower()
    canon = STATUS_ALIASES.get(key)
    if canon is None:
        raise _err(PARAM_INVALID,
                   f"parse_status: unknown status {value!r} (valid: {', '.join(STATUSES)})")
    return canon


def validate_path(path: str) -> str:
    """Path hygiene (CWE-22/CWE-59), parity with ComplianceService::validate_path."""
    if not path or not str(path).strip():
        raise _err(COMPLIANCESVC_ERR_PATH_TRAVERSAL, "Path cannot be empty")
    p = str(path)
    if (".." in p or p.startswith("\\\\") or p.startswith("//")
            or any(ord(c) < 32 or ord(c) == 127 for c in p)):
        raise _err(COMPLIANCESVC_ERR_PATH_TRAVERSAL,
                   f"Path contains forbidden sequences: {p}")
    # Rust Path::extension() == Some("json"): the final path component must
    # end in .json with a non-empty stem (".json" alone has no extension).
    base = p.replace("\\", "/").rsplit("/", 1)[-1]
    if not base.endswith(".json") or base == ".json":
        raise _err(COMPLIANCESVC_ERR_PATH_TRAVERSAL, f"File must have .json extension: {p}")
    if len(p.replace("\\", "/").split("/")) > 16:
        raise _err(COMPLIANCESVC_ERR_PATH_TRAVERSAL,
                   "Path depth exceeds maximum allowed of 16")
    if os.path.lexists(p) and os.path.islink(p):
        raise _err(COMPLIANCESVC_ERR_PATH_TRAVERSAL,
                   f"Symlinks are forbidden for compliance storage: {p}")
    return p


def store_path() -> str:
    """Active store path via the 4-level ladder (T-02906, spec §3.2):
    argument (never available here) → ``AIOSH_COMPLIANCE_MAP_PATH`` →
    config file → the Rust default.

    An env value that fails the hygiene predicate is rejected and the
    default applies (spec §4.3); the result still passes through
    ``validate_path`` at every load/save site.
    """
    from . import compliance_config
    return compliance_config.resolve()["config"]["store_path"]


# --- Persistence (spec §5: canonical byte-stable form) ----------------------

def _snapshot_to_obj(snap: ComplianceCatalogSnapshot) -> dict:
    return {
        "version": snap.version,
        "mappings": [asdict(m) for m in snap.mappings],
        "generated_at": snap.generated_at,
    }


def _obj_to_snapshot(obj: Any) -> ComplianceCatalogSnapshot:
    if not isinstance(obj, dict) or not all(k in obj for k in ("version", "mappings", "generated_at")):
        raise _err(COMPLIANCESVC_ERR_PARSE, "Failed deserializing JSON: missing snapshot fields")
    mappings = obj["mappings"]
    if not isinstance(mappings, list):
        raise _err(COMPLIANCESVC_ERR_PARSE, "Failed deserializing JSON: mappings must be a list")
    entries: list[ComplianceMappingEntry] = []
    for m in mappings:
        if not isinstance(m, dict):
            raise _err(COMPLIANCESVC_ERR_PARSE, "Failed deserializing JSON: entry must be an object")
        entries.append(ComplianceMappingEntry(
            id=m.get("id", ""), control_id=m.get("control_id", ""),
            framework=m.get("framework", ""), target_type=m.get("target_type", ""),
            target_ref=m.get("target_ref", ""), threat_ids=m.get("threat_ids", []),
            status=m.get("status", ""), mitigation_summary=m.get("mitigation_summary", ""),
            tags=m.get("tags", []), created_at=m.get("created_at", ""),
            updated_at=m.get("updated_at", "")))
    return ComplianceCatalogSnapshot(
        version=obj["version"], mappings=entries,
        generated_at=obj["generated_at"])


def load_store(path: str | None = None) -> ComplianceCatalogSnapshot:
    """Load the canonical store (parity with load_from_path). Raises on missing
    file / size cap / parse errors — callers decide the baseline fallback."""
    p = validate_path(path or store_path())
    if not os.path.exists(p):
        raise _err(COMPLIANCESVC_ERR_IO, f"Compliance store file not found: {p}")
    size = os.path.getsize(p)
    if size > MAX_COMPLIANCE_STORE_SIZE:
        raise _err(COMPLIANCESVC_ERR_FILE_SIZE,
                   f"File size {size} exceeds maximum allowed {MAX_COMPLIANCE_STORE_SIZE}")
    try:
        # Bounded read (hardening T-02900): even if the file grows between
        # getsize and read (TOCTOU), never load more than cap+1 bytes —
        # an oversized store fails FILE_SIZE loudly instead of loading
        # unbounded.
        with open(p, "rb") as f:
            raw = f.read(MAX_COMPLIANCE_STORE_SIZE + 1)
    except OSError as exc:
        raise _err(COMPLIANCESVC_ERR_IO, f"Failed reading file: {exc}") from exc
    if len(raw) > MAX_COMPLIANCE_STORE_SIZE:
        raise _err(COMPLIANCESVC_ERR_FILE_SIZE,
                   f"File size {len(raw)} exceeds maximum allowed "
                   f"{MAX_COMPLIANCE_STORE_SIZE}")
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise _err(COMPLIANCESVC_ERR_PARSE, f"Failed deserializing JSON: {exc}") from exc
    return _obj_to_snapshot(obj)


def save_store(path: str | None, snapshot: ComplianceCatalogSnapshot) -> str:
    """Atomic byte-stable write (spec §5): UTF-8, LF, 2-space indent,
    key order preserved, tmp file in the same dir + os.replace."""
    p = validate_path(path or store_path())
    parent = os.path.dirname(p) or "."
    try:
        os.makedirs(parent, exist_ok=True)
    except OSError as exc:
        raise _err(COMPLIANCESVC_ERR_IO, f"Failed creating parent directory: {exc}") from exc
    tmp = os.path.join(
        parent, f".{os.path.basename(p)}.tmp.{os.getpid()}.{time.time_ns()}")
    payload = json.dumps(_snapshot_to_obj(snapshot), indent=2, ensure_ascii=False,
                         separators=(",", ": "))
    # Fail loud before creating any file handle: a store above the read cap
    # could be registered but never loaded again (Python or Rust) — refuse
    # the write with an explicit FILE_SIZE envelope (T-02900).
    payload_len = len(payload.encode("utf-8"))
    if payload_len > MAX_COMPLIANCE_STORE_SIZE:
        raise _err(COMPLIANCESVC_ERR_FILE_SIZE,
                   f"Payload size {payload_len} exceeds maximum allowed "
                   f"{MAX_COMPLIANCE_STORE_SIZE}")
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            f.write(payload)
        os.replace(tmp, p)
    except OSError as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise _err(COMPLIANCESVC_ERR_IO, f"Failed atomic write: {exc}") from exc
    return p


def canonical_baseline() -> ComplianceCatalogSnapshot:
    """The four built-in mappings from ComplianceCatalogSnapshot::canonical_baseline."""
    now = utcnow_iso()

    def _e(eid, control, fw, tt, tref, threats, status, mit, tags):
        return ComplianceMappingEntry(
            id=eid, control_id=control, framework=fw, target_type=tt,
            target_ref=tref, threat_ids=list(threats), status=status,
            mitigation_summary=mit, tags=list(tags),
            created_at=now, updated_at=now)

    return ComplianceCatalogSnapshot(version="1.0.0", generated_at=now, mappings=[
        _e("MAP-NIST-AC3-PEP", "AC-3", "nist_sp_800_53_rev5", "pep_gate",
           "pep_enforce_gate", ["T-EOP-001"], "compliant",
           "Enforced via AIOS Security Kernel PEP gate validation on all syscalls and capability invocations.",
           ["access_control", "kernel"]),
        _e("MAP-NIST-AU2-RING", "AU-2", "nist_sp_800_53_rev5", "audit_ring",
           "audit_ring_commit", ["T-REP-001"], "compliant",
           "Append-only SHA-256 hash-chained SQLite WAL audit ring records consequential security events.",
           ["audit", "wal"]),
        _e("MAP-SOC2-CC61-PEP", "CC6.1", "soc2_type2", "pep_gate",
           "capability_grant_gate", ["T-EOP-002"], "compliant",
           "Access rights restricted using bounded cryptographic capability tokens.",
           ["soc2", "capabilities"]),
        _e("MAP-CIS-CTRL6-PEP", "CIS-6", "cis_controls_v8", "constitution_rule",
           "R-01", ["T-EOP-001"], "compliant",
           "Access Control Management governed by Constitution Rules and PEP gating.",
           ["cis", "constitution"]),
    ])


def init_store(path: str | None = None) -> ComplianceCatalogSnapshot:
    """Create the store with the canonical baseline. Raises STORE_EXISTS."""
    p = validate_path(path or store_path())
    if os.path.exists(p):
        raise _err(STORE_EXISTS, f"Compliance store already exists at '{p}'")
    snap = canonical_baseline()
    save_store(p, snap)
    return snap


# --- Query / mutation operations -------------------------------------------

def list_mappings(snapshot: ComplianceCatalogSnapshot,
                  framework: str | None = None,
                  status: str | None = None) -> list[ComplianceMappingEntry]:
    out = list(snapshot.mappings)
    if framework is not None:
        out = [m for m in out if m.framework == framework]
    if status is not None:
        out = [m for m in out if m.status == status]
    return out


def get_mapping(snapshot: ComplianceCatalogSnapshot, id: str) -> ComplianceMappingEntry | None:
    return next((m for m in snapshot.mappings if m.id == id), None)


def build_entry(
    *,
    id: str,
    control_id: str,
    framework: str,
    target_type: str,
    target_ref: str,
    status: str,
    threat_ids: list[str] | None = None,
    mitigation_summary: str | None = None,
    tags: list[str] | None = None,
) -> ComplianceMappingEntry:
    """Parity with ComplianceMappingEntry::new: identical validation order."""
    validate_identifier(id, "Mapping ID")
    validate_identifier(control_id, "Control ID")
    if target_type not in TARGET_TYPES:
        raise _err(PARAM_INVALID,
                   f"Invalid target-type {target_type!r}. Valid options: "
                   f"{', '.join(TARGET_TYPES)}")
    if not (target_ref or "").strip():
        raise _err(COMPLIANCE_ERR_MISSING_SUBSTRATE_REF, "Substrate target ref cannot be empty")
    validate_text_length(target_ref, MAX_COMPLIANCE_ID_LEN, "Substrate target ref")
    mitigation = mitigation_summary or ""
    validate_text_length(mitigation, MAX_COMPLIANCE_NOTES_LEN, "Mitigation summary")
    if status == "compliant" and not mitigation.strip():
        raise _err(COMPLIANCE_ERR_BOUNDS_EXCEEDED,
                   "Status 'compliant' requires a non-empty mitigation summary")
    threats = list(threat_ids or [])
    if len(threats) > MAX_THREAT_IDS_COUNT:
        raise _err(COMPLIANCE_ERR_BOUNDS_EXCEEDED,
                   f"Threat IDs count exceeds maximum {MAX_THREAT_IDS_COUNT}")
    for tid in threats:
        validate_identifier(tid, "Threat ID")
    tag_list = list(tags or [])
    if len(tag_list) > MAX_TAGS_COUNT:
        raise _err(COMPLIANCE_ERR_BOUNDS_EXCEEDED,
                   f"Tags count exceeds maximum {MAX_TAGS_COUNT}")
    for tag in tag_list:
        validate_identifier(tag, "Tag")
    now = utcnow_iso()
    return ComplianceMappingEntry(
        id=id, control_id=control_id, framework=framework, target_type=target_type,
        target_ref=target_ref, threat_ids=threats, status=status,
        mitigation_summary=mitigation, tags=tag_list,
        created_at=now, updated_at=now)


def register_mapping(snapshot: ComplianceCatalogSnapshot,
                     entry: ComplianceMappingEntry,
                     policy: Any | None = None) -> ComplianceCatalogSnapshot:
    """Parity with add_mapping: capacity, then duplicate id, then push."""
    if policy is not None:
        v = policy.evaluate_registration(entry)
        if v.verdict == "deny":
            raise _err(v.code or "COMPLIANCEPOL_ERR_DENIED", v.reason or "Denied by security policy")
        v_cap = policy.evaluate_capacity(len(snapshot.mappings))
        if v_cap.verdict == "deny":
            raise _err(v_cap.code or "COMPLIANCEPOL_ERR_CAPACITY_EXCEEDED", v_cap.reason or "Capacity exceeded")
    if len(snapshot.mappings) >= MAX_COMPLIANCE_ENTRIES_CAPACITY:
        raise _err(COMPLIANCE_ERR_BOUNDS_EXCEEDED, "Catalog capacity exceeded")
    if any(m.id == entry.id for m in snapshot.mappings):
        raise _err(COMPLIANCE_ERR_DUPLICATE_ID, f"Duplicate mapping ID {entry.id}")
    snapshot.mappings.append(entry)
    snapshot.generated_at = utcnow_iso()
    return snapshot


def can_transition(current: str, nxt: str) -> bool:
    """Parity with can_transition_to: enumerated arms + `_ => true` fallback
    (see STATUS_TRANSITIONS note) — every transition is legal."""
    return True


def update_status(snapshot: ComplianceCatalogSnapshot, id: str,
                  status: str, reason: str | None = None,
                  policy: Any | None = None) -> ComplianceMappingEntry:
    """Parity with update_status/transition_to (incl. the compliant-without-
    summary guard). Raises COMPLIANCESVC_ERR_NOT_FOUND / *_INVALID_STATUS_TRANSITION."""
    entry = get_mapping(snapshot, id)
    if entry is None:
        raise _err(COMPLIANCESVC_ERR_NOT_FOUND, f"Mapping ID '{id}' not found")
    if not can_transition(entry.status, status):
        raise _err(COMPLIANCE_ERR_INVALID_STATUS_TRANSITION,
                   f"Cannot transition from {entry.status} to {status}")
    if policy is not None:
        v = policy.evaluate_status_transition(id, status, reason or "")
        if v.verdict == "deny":
            raise _err(v.code or "COMPLIANCEPOL_ERR_DENIED", v.reason or "Denied by security policy")
    if (status == "compliant" and not entry.mitigation_summary.strip()
            and not (reason or "").strip()):
        raise _err(COMPLIANCE_ERR_BOUNDS_EXCEEDED,
                   "Cannot transition to compliant without mitigation summary or reason")
    entry.status = status
    entry.updated_at = utcnow_iso()
    snapshot.generated_at = utcnow_iso()
    return entry


def assess_framework(snapshot: ComplianceCatalogSnapshot,
                     framework: str | None = None) -> ComplianceAssessmentReport:
    """Parity with assess_framework: counts, percentage = compliant/total*100
    (100.0 when empty), gaps = partially + non_compliant control ids in order."""
    targets = ([m for m in snapshot.mappings if m.framework == framework]
               if framework is not None else list(snapshot.mappings))
    compliant = sum(1 for m in targets if m.status == "compliant")
    partially = sum(1 for m in targets if m.status == "partially_compliant")
    non_compliant = sum(1 for m in targets if m.status == "non_compliant")
    not_applicable = sum(1 for m in targets if m.status == "not_applicable")
    total = len(targets)
    percentage = 100.0 if total == 0 else (compliant / total) * 100.0
    gaps = [m.control_id for m in targets
            if m.status in ("partially_compliant", "non_compliant")]
    return ComplianceAssessmentReport(
        total_mappings=total, compliant_count=compliant,
        partially_compliant_count=partially, non_compliant_count=non_compliant,
        not_applicable_count=not_applicable, compliance_percentage=percentage,
        gap_control_ids=gaps, evaluated_at=utcnow_iso())


def verify_pep_coverage(snapshot: ComplianceCatalogSnapshot, gate_id: str) -> bool:
    """Parity with verify_pep_coverage: pep_gate target + target_ref == gate_id
    + status compliant|partially_compliant."""
    return any(
        m.target_type == "pep_gate" and m.target_ref == gate_id
        and m.status in ("compliant", "partially_compliant")
        for m in snapshot.mappings)


def uncovered_pep_gates(snapshot: ComplianceCatalogSnapshot,
                        required_gates: list[str]) -> list[str]:
    return [g for g in required_gates if not verify_pep_coverage(snapshot, g)]


# --- Tool-facing dispatcher (spec §2/§3/§4) ---------------------------------

def _load_or_baseline(path: str) -> ComplianceCatalogSnapshot:
    """CLI parity: missing store => canonical baseline (read-only, no write)."""
    if not os.path.exists(path):
        return canonical_baseline()
    return load_store(path)


def execute(
    action: str,
    *,
    id: str | None = None,
    framework: str | None = None,
    status: str | None = None,
    control_id: str | None = None,
    target_type: str | None = None,
    target_ref: str | None = None,
    threat_ids: list[str] | None = None,
    mitigation_summary: str | None = None,
    tags: list[str] | None = None,
    reason: str | None = None,
    gate_id: str | None = None,
    grant_id: str | None = None,
) -> dict:
    """Validate -> operate -> spec §3 envelope. Raises ValueError('CODE: msg')
    on failure; the tool wrapper maps these to the spec §4 error envelope and
    the single audit row is written by _recorded_call either way (§7)."""
    if action not in ACTIONS:
        raise _err(PARAM_INVALID,
                   f"execute: unknown action {action!r} (valid: {', '.join(ACTIONS)})")
    path = validate_path(store_path())

    if action == "list":
        fw = parse_framework(framework) if framework is not None else None
        st = parse_status(status) if status is not None else None
        mappings = list_mappings(_load_or_baseline(path), framework=fw, status=st)
        return {"ok": True, "action": "list", "count": len(mappings),
                "mappings": [asdict(m) for m in mappings]}

    if action == "show":
        if not (id or "").strip():
            raise _err(PARAM_INVALID, "show: required parameter 'id' missing")
        entry = get_mapping(_load_or_baseline(path), id)
        if entry is None:
            raise _err(COMPLIANCESVC_ERR_NOT_FOUND,
                       f"Mapping ID '{id}' not found")
        return {"ok": True, "action": "show", "mapping": asdict(entry)}

    if action == "register":
        # Missing (None) parameters are PARAM_INVALID; empty/whitespace values
        # flow to the Rust-parity domain validators (e.g. blank target_ref ->
        # MISSING_SUBSTRATE_REF, blank id -> INVALID_ID).
        for name, value in (("id", id), ("control_id", control_id),
                            ("framework", framework), ("target_type", target_type),
                            ("target_ref", target_ref)):
            if value is None:
                raise _err(PARAM_INVALID, f"register: required parameter '{name}' missing")
        fw = parse_framework(framework)
        st = parse_status(status) if status is not None else "non_compliant"
        entry = build_entry(
            id=id, control_id=control_id, framework=fw, target_type=target_type,
            target_ref=target_ref, status=st,
            threat_ids=threat_ids, mitigation_summary=mitigation_summary,
            tags=tags)
        snap = _load_or_baseline(path)
        register_mapping(snap, entry)
        save_store(path, snap)
        return {"ok": True, "action": "register", "mapping": asdict(entry)}

    if action == "status":
        if not (id or "").strip():
            raise _err(PARAM_INVALID, "status: required parameter 'id' missing")
        if status is None:
            raise _err(PARAM_INVALID, "status: required parameter 'status' missing")
        st = parse_status(status)
        snap = _load_or_baseline(path)
        entry = update_status(snap, id, st, reason)
        save_store(path, snap)
        return {"ok": True, "action": "status", "mapping": asdict(entry)}

    if action == "assess":
        fw = parse_framework(framework) if framework is not None else None
        report = assess_framework(_load_or_baseline(path), framework=fw)
        return {"ok": True, "action": "assess", "report": asdict(report)}

    if action == "check-pep":
        if not (gate_id or "").strip():
            raise _err(PARAM_INVALID, "check-pep: required parameter 'gate_id' missing")
        snap = _load_or_baseline(path)
        covered = verify_pep_coverage(snap, gate_id)
        return {"ok": True, "action": "check-pep", "gate_id": gate_id,
                "covered": covered,
                "uncovered_required": [] if covered else [gate_id]}

    if action == "stats":
        from .compliance_observability import generate_compliance_observability_report
        snap = _load_or_baseline(path)
        report = generate_compliance_observability_report(snap, policy=None, ring=None)
        return {"ok": True, "action": "stats", "report": asdict(report)}

    # action == "init"
    snap = init_store(path)
    return {"ok": True, "action": "init", "initialized": True, "path": path,
            "count": len(snap.mappings), "version": snap.version}
