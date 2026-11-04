"""Agent Loop Hardening security policy (T-03325 scaffold).

Spec: docs/tasks/evidence/T-03324-spec.md. Adds dispatch Gate #1 (the Constitution
classifier) and the grant's ``max_irreversible`` budget to every loop step
(LOOPPOL-INV1..LOOPPOL-INV4).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

LOOPPOL_ERR_CONSTITUTION = "LOOPPOL_ERR_CONSTITUTION"
LOOPPOL_ERR_IRREVERSIBLE_BUDGET = "LOOPPOL_ERR_IRREVERSIBLE_BUDGET"

#: Irreversible by name; mirrors ``audit_client.grant_check``.
IRREVERSIBLE_PREFIXES = ("pentest.", "fs.write")
IRREVERSIBLE_TOOLS = ("system.reboot", "system.shutdown")


@dataclass(frozen=True)
class StepPolicy:
    """Result of evaluating one step against the constitution."""

    classification: Dict[str, Any] = field(default_factory=dict)
    refused_reason: Optional[str] = None
    irreversible: bool = False


def is_irreversible(tool: Optional[str], classification: Dict[str, Any]) -> bool:
    raise NotImplementedError("T-03326: is_irreversible")


def evaluate_step(tool: Optional[str], target: Optional[str], args: Dict[str, Any]) -> StepPolicy:
    raise NotImplementedError("T-03326: evaluate_step")
