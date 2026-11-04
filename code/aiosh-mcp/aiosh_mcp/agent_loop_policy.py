"""Agent Loop Hardening security policy (T-03325 scaffold / T-03326 impl).

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


#: Classification recorded for a pure reasoning step (no tool): nothing fires but C-4 (audit ring).
def _reasoning_classification() -> Dict[str, Any]:
    from aiosh_mcp.classifier import CLASSIFIER_REVISION
    return {"c_flags": {"c1": False, "c2": False, "c3": False, "c4": True},
            "policy_revision": CLASSIFIER_REVISION, "classify_rule_ids": [],
            "classify_evidence": {"c1": [], "c2": [], "c3": [], "c4": []},
            "classify_overall_verdict": "ok", "classify_verdict_reason": "reasoning step (no tool)"}


def audit_fields(result: Dict[str, Any]) -> Dict[str, Any]:
    """Maps ``classify(...).to_dict()`` onto the audit-row columns, exactly as ``_dispatch`` does."""
    from aiosh_mcp._dispatch import _classify_evidence, _classify_to_c_flags
    return {"c_flags": _classify_to_c_flags(result), "policy_revision": result.get("policy_revision"),
            "classify_rule_ids": list(result.get("rule_ids") or []), "classify_evidence": _classify_evidence(result),
            "classify_overall_verdict": result.get("overall_verdict", "ok"),
            "classify_verdict_reason": result.get("verdict_reason", "")}


def is_irreversible(tool: Optional[str], classification: Dict[str, Any]) -> bool:
    """Irreversible by name (same set as ``audit_client.grant_check``) or by the classifier's C-3 flag."""
    if not tool:
        return False
    if tool.startswith(IRREVERSIBLE_PREFIXES) or tool in IRREVERSIBLE_TOOLS:
        return True
    return bool(classification.get("c_flags", {}).get("c3"))


def evaluate_step(tool: Optional[str], target: Optional[str], args: Dict[str, Any]) -> StepPolicy:
    """Constitution gate (P2) for one loop step; fails closed if the classifier errors."""
    if not tool:
        return StepPolicy(classification=_reasoning_classification())
    try:
        from aiosh_mcp.classifier import classify
        result = classify(tool, target, args).to_dict()
        fields = audit_fields(result)
    except Exception as exc:  # fail closed (T-03324 §4)
        return StepPolicy(classification=_reasoning_classification() | {
            "classify_overall_verdict": "refused", "classify_verdict_reason": f"classifier unavailable: {exc}"},
            refused_reason=f"{LOOPPOL_ERR_CONSTITUTION}: classifier unavailable", irreversible=True)
    refused = None
    if fields["classify_overall_verdict"] == "refused":
        refused = (f"{LOOPPOL_ERR_CONSTITUTION}: {fields['classify_verdict_reason'] or 'refused'} "
                   f"(rules {','.join(fields['classify_rule_ids'])}; policy {fields['policy_revision']})")
    return StepPolicy(classification=fields, refused_reason=refused, irreversible=is_irreversible(tool, fields))
