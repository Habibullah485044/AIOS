"""Incident Response Runbooks Data Model (IR-INV1..IR-INV5).

Provides domain models, incident categories, severity levels, phases,
steps, and catalog snapshots for Incident Response Runbooks.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
import re
from typing import Any

from .audit_client import utcnow_iso

MAX_RUNBOOK_ID_LEN = 64
MAX_RUNBOOK_TITLE_LEN = 128
MAX_RUNBOOK_DESC_LEN = 2048
MAX_RUNBOOK_STEPS_COUNT = 32
MAX_RUNBOOK_TAGS_COUNT = 16
MAX_RUNBOOK_CATALOG_CAPACITY = 256

RUNBOOK_ERR_INVALID_ID = "RUNBOOK_ERR_INVALID_ID"
RUNBOOK_ERR_INVALID_TITLE = "RUNBOOK_ERR_INVALID_TITLE"
RUNBOOK_ERR_BOUNDS_EXCEEDED = "RUNBOOK_ERR_BOUNDS_EXCEEDED"
RUNBOOK_ERR_CONTROL_CHARS = "RUNBOOK_ERR_CONTROL_CHARS"
RUNBOOK_ERR_DUPLICATE_ID = "RUNBOOK_ERR_DUPLICATE_ID"
RUNBOOK_ERR_EMPTY_STEPS = "RUNBOOK_ERR_EMPTY_STEPS"


class IncidentSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def parse_severity(cls, s: str) -> "IncidentSeverity":
        normalized = s.strip().lower()
        mapping = {
            "low": cls.LOW,
            "medium": cls.MEDIUM,
            "med": cls.MEDIUM,
            "high": cls.HIGH,
            "critical": cls.CRITICAL,
            "crit": cls.CRITICAL,
        }
        if normalized in mapping:
            return mapping[normalized]
        raise ValueError(f"{RUNBOOK_ERR_BOUNDS_EXCEEDED}: Unknown severity '{s}'")


class IncidentCategory(str, Enum):
    MALWARE_CONTAINMENT = "malware_containment"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_EXFILTRATION = "data_exfiltration"
    DENIAL_OF_SERVICE = "denial_of_service"
    INTEGRITY_VIOLATION = "integrity_violation"
    POLICY_BYPASS_ATTEMPT = "policy_bypass_attempt"

    @classmethod
    def parse_category(cls, s: str) -> "IncidentCategory":
        normalized = s.strip().lower()
        mapping = {
            "malware_containment": cls.MALWARE_CONTAINMENT,
            "malware": cls.MALWARE_CONTAINMENT,
            "unauthorized_access": cls.UNAUTHORIZED_ACCESS,
            "access": cls.UNAUTHORIZED_ACCESS,
            "data_exfiltration": cls.DATA_EXFILTRATION,
            "exfiltration": cls.DATA_EXFILTRATION,
            "denial_of_service": cls.DENIAL_OF_SERVICE,
            "dos": cls.DENIAL_OF_SERVICE,
            "integrity_violation": cls.INTEGRITY_VIOLATION,
            "integrity": cls.INTEGRITY_VIOLATION,
            "policy_bypass_attempt": cls.POLICY_BYPASS_ATTEMPT,
            "bypass": cls.POLICY_BYPASS_ATTEMPT,
        }
        if normalized in mapping:
            return mapping[normalized]
        raise ValueError(f"{RUNBOOK_ERR_BOUNDS_EXCEEDED}: Unknown incident category '{s}'")


class RunbookPhase(str, Enum):
    PREPARATION = "preparation"
    DETECTION = "detection"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    POST_INCIDENT = "post_incident"

    @classmethod
    def parse_phase(cls, s: str) -> "RunbookPhase":
        normalized = s.strip().lower()
        mapping = {
            "preparation": cls.PREPARATION,
            "prep": cls.PREPARATION,
            "detection": cls.DETECTION,
            "detect": cls.DETECTION,
            "containment": cls.CONTAINMENT,
            "contain": cls.CONTAINMENT,
            "eradication": cls.ERADICATION,
            "eradicate": cls.ERADICATION,
            "recovery": cls.RECOVERY,
            "recover": cls.RECOVERY,
            "post_incident": cls.POST_INCIDENT,
            "post": cls.POST_INCIDENT,
        }
        if normalized in mapping:
            return mapping[normalized]
        raise ValueError(f"{RUNBOOK_ERR_BOUNDS_EXCEEDED}: Unknown runbook phase '{s}'")


class RunbookTargetSubstrate(str, Enum):
    PROCESS = "process"
    NETWORK = "network"
    IDENTITY = "identity"
    AUDIT_RING = "audit_ring"
    STORAGE = "storage"

    @classmethod
    def parse_target(cls, s: str) -> "RunbookTargetSubstrate":
        normalized = s.strip().lower()
        mapping = {
            "process": cls.PROCESS,
            "proc": cls.PROCESS,
            "network": cls.NETWORK,
            "net": cls.NETWORK,
            "identity": cls.IDENTITY,
            "id": cls.IDENTITY,
            "token": cls.IDENTITY,
            "audit_ring": cls.AUDIT_RING,
            "audit": cls.AUDIT_RING,
            "ring": cls.AUDIT_RING,
            "storage": cls.STORAGE,
            "disk": cls.STORAGE,
            "fs": cls.STORAGE,
        }
        if normalized in mapping:
            return mapping[normalized]
        raise ValueError(f"{RUNBOOK_ERR_BOUNDS_EXCEEDED}: Unknown substrate target '{s}'")


def validate_identifier(val: str, field_name: str) -> None:
    trimmed = val.strip()
    if not trimmed:
        raise ValueError(f"{RUNBOOK_ERR_INVALID_ID}: {field_name} cannot be empty")
    if len(trimmed) > MAX_RUNBOOK_ID_LEN:
        raise ValueError(f"{RUNBOOK_ERR_BOUNDS_EXCEEDED}: {field_name} exceeds max length {MAX_RUNBOOK_ID_LEN}")
    if not re.match(r"^[a-zA-Z0-9_\-\.]+$", trimmed):
        raise ValueError(f"{RUNBOOK_ERR_INVALID_ID}: {field_name} contains invalid characters")


def validate_title(val: str, field_name: str) -> None:
    trimmed = val.strip()
    if not trimmed:
        raise ValueError(f"{RUNBOOK_ERR_INVALID_TITLE}: {field_name} cannot be empty")
    if len(trimmed) > MAX_RUNBOOK_TITLE_LEN:
        raise ValueError(f"{RUNBOOK_ERR_BOUNDS_EXCEEDED}: {field_name} exceeds max length {MAX_RUNBOOK_TITLE_LEN}")
    if any(ord(c) < 32 for c in trimmed):
        raise ValueError(f"{RUNBOOK_ERR_CONTROL_CHARS}: {field_name} contains control characters")


def validate_text_length(val: str, max_len: usize if 'usize' in globals() else int, field_name: str) -> None:
    if len(val) > max_len:
        raise ValueError(f"{RUNBOOK_ERR_BOUNDS_EXCEEDED}: {field_name} exceeds max length {max_len}")
    if any(ord(c) < 32 and c not in ('\n', '\r', '\t') for c in val):
        raise ValueError(f"{RUNBOOK_ERR_CONTROL_CHARS}: {field_name} contains control characters")


@dataclass
class RunbookStep:
    id: str
    title: str
    phase: RunbookPhase
    target: RunbookTargetSubstrate
    action_template: str
    automated: bool = True
    requires_confirmation: bool = False
    timeout_seconds: int = 30

    def __post_init__(self):
        validate_identifier(self.id, "Step ID")
        validate_title(self.title, "Step title")
        validate_text_length(self.action_template, MAX_RUNBOOK_DESC_LEN, "Action template")
        if isinstance(self.phase, str):
            self.phase = RunbookPhase.parse_phase(self.phase)
        if isinstance(self.target, str):
            self.target = RunbookTargetSubstrate.parse_target(self.target)
        if self.timeout_seconds <= 0:
            self.timeout_seconds = 30


@dataclass
class RunbookSpec:
    id: str
    title: str
    category: IncidentCategory
    severity: IncidentSeverity
    description: str
    steps: list[RunbookStep]
    tags: list[str] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self):
        validate_identifier(self.id, "Runbook ID")
        validate_title(self.title, "Runbook title")
        validate_text_length(self.description, MAX_RUNBOOK_DESC_LEN, "Runbook description")
        if isinstance(self.category, str):
            self.category = IncidentCategory.parse_category(self.category)
        if isinstance(self.severity, str):
            self.severity = IncidentSeverity.parse_severity(self.severity)
        if not self.steps:
            raise ValueError(f"{RUNBOOK_ERR_EMPTY_STEPS}: Runbook must contain at least one step")
        if len(self.steps) > MAX_RUNBOOK_STEPS_COUNT:
            raise ValueError(f"{RUNBOOK_ERR_BOUNDS_EXCEEDED}: Steps count exceeds {MAX_RUNBOOK_STEPS_COUNT}")
        if len(self.tags) > MAX_RUNBOOK_TAGS_COUNT:
            raise ValueError(f"{RUNBOOK_ERR_BOUNDS_EXCEEDED}: Tags count exceeds {MAX_RUNBOOK_TAGS_COUNT}")
        for t in self.tags:
            validate_identifier(t, "Tag")
        now = utcnow_iso()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now


@dataclass
class RunbookCatalogSnapshot:
    version: str
    runbooks: list[RunbookSpec]
    generated_at: str = ""

    def __post_init__(self):
        if not self.generated_at:
            self.generated_at = utcnow_iso()

    @classmethod
    def canonical_baseline(cls) -> "RunbookCatalogSnapshot":
        malware_steps = [
            RunbookStep(
                id="STEP-MW-01",
                title="Freeze target malicious process via cgroup/SIGSTOP",
                phase=RunbookPhase.CONTAINMENT,
                target=RunbookTargetSubstrate.PROCESS,
                action_template="aiosh run kill -STOP {target_pid}",
                automated=True,
                requires_confirmation=False,
                timeout_seconds=15,
            ),
            RunbookStep(
                id="STEP-MW-02",
                title="Quarantine network interface and drop outbound connections",
                phase=RunbookPhase.CONTAINMENT,
                target=RunbookTargetSubstrate.NETWORK,
                action_template="aiosh run iptables -A OUTPUT -m owner --uid-owner {target_uid} -j DROP",
                automated=True,
                requires_confirmation=False,
                timeout_seconds=30,
            ),
            RunbookStep(
                id="STEP-MW-03",
                title="Commit forensic state snapshot to append-only audit ring",
                phase=RunbookPhase.POST_INCIDENT,
                target=RunbookTargetSubstrate.AUDIT_RING,
                action_template="aiosh audit checkpoint --reason 'Malware containment forensic snapshot'",
                automated=True,
                requires_confirmation=False,
                timeout_seconds=10,
            ),
        ]

        access_steps = [
            RunbookStep(
                id="STEP-UA-01",
                title="Revoke active capability tokens for compromised actor",
                phase=RunbookPhase.CONTAINMENT,
                target=RunbookTargetSubstrate.IDENTITY,
                action_template="aiosh grant revoke {grant_id}",
                automated=True,
                requires_confirmation=False,
                timeout_seconds=10,
            ),
            RunbookStep(
                id="STEP-UA-02",
                title="Terminate unauthorized operator session",
                phase=RunbookPhase.CONTAINMENT,
                target=RunbookTargetSubstrate.IDENTITY,
                action_template="aiosh session terminate {session_id}",
                automated=True,
                requires_confirmation=True,
                timeout_seconds=30,
            ),
        ]

        baseline = [
            RunbookSpec(
                id="RB-IR-MALWARE-01",
                title="Rapid Malware Containment & Process Freeze",
                category=IncidentCategory.MALWARE_CONTAINMENT,
                severity=IncidentSeverity.HIGH,
                description="Emergency containment protocol for suspicious execution or active malware.",
                steps=malware_steps,
                tags=["malware", "emergency", "containment"],
            ),
            RunbookSpec(
                id="RB-IR-ACCESS-01",
                title="Unauthorized Access Remediation & Token Revocation",
                category=IncidentCategory.UNAUTHORIZED_ACCESS,
                severity=IncidentSeverity.CRITICAL,
                description="Immediate revocation and eviction protocol following unauthorized credential access.",
                steps=access_steps,
                tags=["access", "token", "eviction"],
            ),
        ]
        return cls(version="1.0.0", runbooks=baseline)

    def add_runbook(self, runbook: RunbookSpec) -> None:
        if len(self.runbooks) >= MAX_RUNBOOK_CATALOG_CAPACITY:
            raise ValueError(f"{RUNBOOK_ERR_BOUNDS_EXCEEDED}: Runbook catalog capacity exceeded")
        if any(r.id == runbook.id for r in self.runbooks):
            raise ValueError(f"{RUNBOOK_ERR_DUPLICATE_ID}: Duplicate runbook ID {runbook.id}")
        self.runbooks.append(runbook)
        self.generated_at = utcnow_iso()

    def get_runbook(self, id: str) -> RunbookSpec | None:
        for r in self.runbooks:
            if r.id == id:
                return r
        return None

    def remove_runbook(self, id: str) -> RunbookSpec | None:
        for i, r in enumerate(self.runbooks):
            if r.id == id:
                self.generated_at = utcnow_iso()
                return self.runbooks.pop(i)
        return None
