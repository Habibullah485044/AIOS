"""Agent Loop Hardening security policy (T-03325 scaffold / T-03326 impl / T-03329 sec).

Spec: docs/tasks/evidence/T-03324-spec.md. Adds dispatch Gate #1 (the Constitution
classifier) and the grant's ``max_irreversible`` budget to every loop step
(LOOPPOL-INV1..LOOPPOL-INV4).
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence

LOOPPOL_ERR_CONSTITUTION = "LOOPPOL_ERR_CONSTITUTION"
LOOPPOL_ERR_IRREVERSIBLE_BUDGET = "LOOPPOL_ERR_IRREVERSIBLE_BUDGET"

#: Irreversible by name; mirrors ``audit_client.grant_check`` plus process/shell execution (T-03329).
#: A prefix ending in "." also covers the bare family name ("pentest" is covered by grant glob "pentest.*").
IRREVERSIBLE_PREFIXES = ("pentest.", "fs.write", "process.", "shell.")
IRREVERSIBLE_TOOLS = ("system.reboot", "system.shutdown")

#: tool_args keys whose values are call targets checked against scope.paths / scope.networks (T-03329).
TARGET_ARG_KEYS = ("target", "targets", "path", "paths", "host", "hosts", "url", "urls", "uri", "file", "files",
                   "filename", "dest", "destination", "src", "source", "dir", "directory", "address", "ip", "cwd")
LOOPPOL_ERR_TARGET = "LOOPPOL_ERR_TARGET"
_INVISIBLE = re.compile("[\u200b-\u200f\u2060-\u2064\ufeff\u00ad]")


def normalize_text(text: str) -> str:
    """NFKC + casefold, invisible characters removed, Unicode spaces collapsed (classifier input only)."""
    text = _INVISIBLE.sub("", unicodedata.normalize("NFKC", text))
    return " ".join(text.split()).casefold().rstrip(".") if text else text


def _normalize(value: Any) -> Any:
    if isinstance(value, str):
        return normalize_text(value)
    if isinstance(value, dict):
        return {normalize_text(str(k)): _normalize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize(v) for v in value]
    return value


def _all_text(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield str(k)
            yield from _all_text(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _all_text(v)


def extract_targets(args: Dict[str, Any]) -> List[str]:
    """Every string under a target-like key (lists included). A non-string value there is an error."""
    out: List[str] = []
    for key, value in (args or {}).items():
        if str(key).casefold() not in TARGET_ARG_KEYS or value is None:
            continue
        items = value if isinstance(value, (list, tuple)) else [value]
        for item in items:
            if not isinstance(item, str):
                raise ValueError(f"{LOOPPOL_ERR_TARGET}: non-string value under target key '{key}'")
            out.append(item)
    return out


def args_digest(args: Optional[Dict[str, Any]]) -> str:
    """SHA-256 of the canonical, *unmasked* args: lets evidence be matched to what actually ran (T-03329 #6)."""
    canon = json.dumps(args or {}, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


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
    t = tool.casefold()
    if t.startswith(IRREVERSIBLE_PREFIXES) or t in IRREVERSIBLE_TOOLS:
        return True
    if any(p.endswith(".") and t == p[:-1] for p in IRREVERSIBLE_PREFIXES):
        return True
    return bool(classification.get("c_flags", {}).get("c3"))


_VERDICT_RANK = {"ok": 0, "caution": 1, "refused": 2}


def evaluate_step(tool: Optional[str], targets: Any, args: Dict[str, Any]) -> StepPolicy:
    """Constitution gate (P2) for one loop step; fails closed if the classifier errors.

    T-03329: the classifier sees *normalised* input (NFKC, casefold, invisible characters removed),
    a flattened copy of every key and nested string (so R-11 cannot be hidden in nested
    dicts/keys), and is run once per target, keeping the most severe verdict.
    """
    if not tool:
        return StepPolicy(classification=_reasoning_classification())
    target_list: Sequence[Optional[str]] = (
        [targets] if isinstance(targets, str) or targets is None else list(targets)) or [None]
    try:
        from aiosh_mcp.classifier import classify
        norm_args = _normalize(args or {})
        if not isinstance(norm_args, dict):
            norm_args = {}
        norm_args["__all_text__"] = " ".join(_all_text(norm_args))
        # An invisible character may stand in for a word break ("ignore​constitution"),
        # so the classifier also sees a copy with invisible characters turned into spaces.
        norm_args["__all_text_spaced__"] = normalize_text(_INVISIBLE.sub(" ", " ".join(
            str(t) for t in _all_text(args or {}))))
        result = None
        for target in target_list:
            r = classify(normalize_text(tool), normalize_text(target) if target else target, norm_args).to_dict()
            if result is None or _VERDICT_RANK.get(r["overall_verdict"], 2) > _VERDICT_RANK.get(
                    result["overall_verdict"], 2):
                result = r
        fields = audit_fields(result)
    except Exception as exc:  # fail closed (T-03324 §4)
        return StepPolicy(classification=_reasoning_classification() | {
            "classify_overall_verdict": "refused", "classify_verdict_reason": f"classifier unavailable: {exc}"},
            refused_reason=f"{LOOPPOL_ERR_CONSTITUTION}: classifier unavailable", irreversible=True)
    refused = None
    if fields["classify_overall_verdict"] == "refused":
        refused = (f"{LOOPPOL_ERR_CONSTITUTION}: {fields['classify_verdict_reason'] or 'refused'} "
                   f"(rules {','.join(fields['classify_rule_ids'])}; policy {fields['policy_revision']})")
    return StepPolicy(classification=fields, refused_reason=refused,
                      irreversible=_registry_irreversible(tool, target_list, fields, is_irreversible(tool, fields)))


def _registry_irreversible(tool: str, targets: Sequence[Optional[str]], fields: Dict[str, Any], legacy: bool) -> bool:
    """Tool registry (T-03378): shadow reports disagreements; strict can only mark a step irreversible. Decided by
    the single policy point (T-03426), which never raises and fails closed if strict was asked for (T-03379 #2)."""
    from aiosh_mcp.tool_registry_policy import evaluate
    return evaluate(tool, targets[0] if targets else None, surface="agent_loop", legacy_irreversible=legacy,
                    classification=fields).irreversible
