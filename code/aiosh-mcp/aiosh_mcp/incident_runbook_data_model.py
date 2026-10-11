"""Incident Response Runbooks Data Model (IR-INV1..IR-INV5).

Provides domain models, incident categories, severity levels, phases,
steps, and catalog snapshots for Incident Response Runbooks.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
import json
import re
from typing import Any

from .audit_client import utcnow_iso

MAX_RUNBOOK_ID_LEN = 64
MAX_RUNBOOK_TITLE_LEN = 128
MAX_RUNBOOK_DESC_LEN = 2048
MAX_RUNBOOK_STEPS_COUNT = 32
MAX_RUNBOOK_TAGS_COUNT = 16
MAX_RUNBOOK_CATALOG_CAPACITY = 256
MAX_RUNBOOK_STEP_TIMEOUT_SECONDS = 3600

RUNBOOK_ERR_INVALID_ID = "RUNBOOK_ERR_INVALID_ID"
RUNBOOK_ERR_INVALID_TITLE = "RUNBOOK_ERR_INVALID_TITLE"
RUNBOOK_ERR_BOUNDS_EXCEEDED = "RUNBOOK_ERR_BOUNDS_EXCEEDED"
RUNBOOK_ERR_CONTROL_CHARS = "RUNBOOK_ERR_CONTROL_CHARS"
RUNBOOK_ERR_DUPLICATE_ID = "RUNBOOK_ERR_DUPLICATE_ID"
RUNBOOK_ERR_EMPTY_STEPS = "RUNBOOK_ERR_EMPTY_STEPS"
RUNBOOK_ERR_INVALID_TEMPLATE = "RUNBOOK_ERR_INVALID_TEMPLATE"


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


def validate_action_template(template: str) -> None:
    if "{" in template or "}" in template:
        idx = 0
        while idx < len(template):
            if template[idx] == "{":
                end = template.find("}", idx + 1)
                if end == -1:
                    raise ValueError(f"{RUNBOOK_ERR_INVALID_TEMPLATE}: Unclosed parameter placeholder in action template")
                param = template[idx + 1:end].strip()
                if not param:
                    raise ValueError(f"{RUNBOOK_ERR_INVALID_TEMPLATE}: Empty parameter placeholder in action template")
                if not re.match(r"^[a-zA-Z0-9_]+$", param):
                    raise ValueError(f"{RUNBOOK_ERR_INVALID_TEMPLATE}: Invalid parameter placeholder '{param}'")
                idx = end + 1
            else:
                idx += 1


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
        validate_action_template(self.action_template)
        if isinstance(self.phase, str):
            self.phase = RunbookPhase.parse_phase(self.phase)
        if isinstance(self.target, str):
            self.target = RunbookTargetSubstrate.parse_target(self.target)
        if self.timeout_seconds <= 0:
            self.timeout_seconds = 30
        if self.timeout_seconds > MAX_RUNBOOK_STEP_TIMEOUT_SECONDS:
            raise ValueError(f"{RUNBOOK_ERR_BOUNDS_EXCEEDED}: Step timeout {self.timeout_seconds}s exceeds maximum {MAX_RUNBOOK_STEP_TIMEOUT_SECONDS}s")

    def is_high_risk(self) -> bool:
        return (
            self.phase == RunbookPhase.ERADICATION
            or self.target == RunbookTargetSubstrate.STORAGE
            or self.requires_confirmation
        )


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
        seen_step_ids = set()
        for step in self.steps:
            if step.id in seen_step_ids:
                raise ValueError(f"{RUNBOOK_ERR_DUPLICATE_ID}: Duplicate step ID {step.id}")
            seen_step_ids.add(step.id)
        now = utcnow_iso()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now

    def steps_for_phase(self, phase: RunbookPhase | str) -> list[RunbookStep]:
        target_phase = phase if isinstance(phase, RunbookPhase) else RunbookPhase.parse_phase(phase)
        return [s for s in self.steps if s.phase == target_phase]

    def steps_for_target(self, target: RunbookTargetSubstrate | str) -> list[RunbookStep]:
        target_sub = target if isinstance(target, RunbookTargetSubstrate) else RunbookTargetSubstrate.parse_target(target)
        return [s for s in self.steps if s.target == target_sub]

    def automated_steps(self) -> list[RunbookStep]:
        return [s for s in self.steps if s.automated]

    def manual_steps(self) -> list[RunbookStep]:
        return [s for s in self.steps if not s.automated or s.requires_confirmation]

    def high_risk_steps(self) -> list[RunbookStep]:
        return [s for s in self.steps if s.is_high_risk()]

    def total_timeout_seconds(self) -> int:
        return sum(s.timeout_seconds for s in self.steps)

    def validate(self) -> None:
        validate_identifier(self.id, "Runbook ID")
        validate_title(self.title, "Runbook title")
        validate_text_length(self.description, MAX_RUNBOOK_DESC_LEN, "Runbook description")
        if not self.steps:
            raise ValueError(f"{RUNBOOK_ERR_EMPTY_STEPS}: Runbook must contain at least one step")
        if len(self.steps) > MAX_RUNBOOK_STEPS_COUNT:
            raise ValueError(f"{RUNBOOK_ERR_BOUNDS_EXCEEDED}: Steps count exceeds {MAX_RUNBOOK_STEPS_COUNT}")
        if len(self.tags) > MAX_RUNBOOK_TAGS_COUNT:
            raise ValueError(f"{RUNBOOK_ERR_BOUNDS_EXCEEDED}: Tags count exceeds {MAX_RUNBOOK_TAGS_COUNT}")
        seen = set()
        for s in self.steps:
            if s.id in seen:
                raise ValueError(f"{RUNBOOK_ERR_DUPLICATE_ID}: Duplicate step ID {s.id}")
            seen.add(s.id)


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

    def find_by_category(self, category: IncidentCategory | str) -> list[RunbookSpec]:
        cat = category if isinstance(category, IncidentCategory) else IncidentCategory.parse_category(category)
        return [r for r in self.runbooks if r.category == cat]

    def find_by_severity(self, severity: IncidentSeverity | str) -> list[RunbookSpec]:
        sev = severity if isinstance(severity, IncidentSeverity) else IncidentSeverity.parse_severity(severity)
        return [r for r in self.runbooks if r.severity == sev]

    def filter_by_phase(self, phase: RunbookPhase | str) -> list[RunbookSpec]:
        target_phase = phase if isinstance(phase, RunbookPhase) else RunbookPhase.parse_phase(phase)
        return [r for r in self.runbooks if any(s.phase == target_phase for s in r.steps)]

    def filter_by_target(self, target: RunbookTargetSubstrate | str) -> list[RunbookSpec]:
        target_sub = target if isinstance(target, RunbookTargetSubstrate) else RunbookTargetSubstrate.parse_target(target)
        return [r for r in self.runbooks if any(s.target == target_sub for s in r.steps)]

    def filter_by_tag(self, tag: str) -> list[RunbookSpec]:
        normalized = tag.strip().lower()
        return [r for r in self.runbooks if any(t.lower() == normalized for t in r.tags)]

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "runbooks": [
                {
                    "id": r.id,
                    "title": r.title,
                    "category": r.category.value if isinstance(r.category, IncidentCategory) else str(r.category),
                    "severity": r.severity.value if isinstance(r.severity, IncidentSeverity) else str(r.severity),
                    "description": r.description,
                    "steps": [
                        {
                            "id": s.id,
                            "title": s.title,
                            "phase": s.phase.value if isinstance(s.phase, RunbookPhase) else str(s.phase),
                            "target": s.target.value if isinstance(s.target, RunbookTargetSubstrate) else str(s.target),
                            "action_template": s.action_template,
                            "automated": s.automated,
                            "requires_confirmation": s.requires_confirmation,
                            "timeout_seconds": s.timeout_seconds,
                        }
                        for s in r.steps
                    ],
                    "tags": r.tags,
                    "created_at": r.created_at,
                    "updated_at": r.updated_at,
                }
                for r in self.runbooks
            ],
            "generated_at": self.generated_at,
        }

    def to_json(self, indent: int | None = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RunbookCatalogSnapshot":
        runbooks = []
        for r_data in data.get("runbooks", []):
            steps = []
            for s_data in r_data.get("steps", []):
                steps.append(
                    RunbookStep(
                        id=s_data["id"],
                        title=s_data["title"],
                        phase=RunbookPhase.parse_phase(s_data["phase"]),
                        target=RunbookTargetSubstrate.parse_target(s_data["target"]),
                        action_template=s_data["action_template"],
                        automated=s_data.get("automated", True),
                        requires_confirmation=s_data.get("requires_confirmation", False),
                        timeout_seconds=s_data.get("timeout_seconds", 30),
                    )
                )
            runbooks.append(
                RunbookSpec(
                    id=r_data["id"],
                    title=r_data["title"],
                    category=IncidentCategory.parse_category(r_data["category"]),
                    severity=IncidentSeverity.parse_severity(r_data["severity"]),
                    description=r_data["description"],
                    steps=steps,
                    tags=r_data.get("tags", []),
                    created_at=r_data.get("created_at", ""),
                    updated_at=r_data.get("updated_at", ""),
                )
            )
        return cls(
            version=data.get("version", "1.0.0"),
            runbooks=runbooks,
            generated_at=data.get("generated_at", ""),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "RunbookCatalogSnapshot":
        return cls.from_dict(json.loads(json_str))

