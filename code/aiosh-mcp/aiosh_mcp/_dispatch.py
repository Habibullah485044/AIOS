"""Sprint 1 — MCP dispatch helper.

Every MCP tool routed from the AI to a host action must:

  1. Be classified for Constitution C-1..C-4 flagging.
  2. Be authorized by a valid PEP grant (or refused with reason).
  3. Emit exactly one audit row whose hash extends the chain.
  4. Return the row id alongside the tool result so the caller can
     cross-reference the audit and the action.

This module is intentionally small. The pattern is:

    def tool(args, grant_id):
        with audit_client.open_db() as conn:
            verdict = audit_client.grant_check(conn, grant_id, tool, target)
            if not verdict["ok"]:
                row = _append(conn, "refused", verdict["reason"], args, grant_id)
                return {"ok": False, "tool": tool, ...,
                        "audit_id": row.id, "reason": verdict["reason"]}
            try:
                result = do_the_thing(...)
                row = _append(conn, "ok", None, args, grant_id)
                return {"ok": True, "tool": tool, ...,
                        "audit_id": row.id, "result": result}
            except SomeError as e:
                row = _append(conn, "error", str(e), args, grant_id)
                return {"ok": False, "tool": tool, ...,
                        "audit_id": row.id, "error": str(e)}
"""

from __future__ import annotations
import os
from contextlib import contextmanager
from typing import Any, Callable, Iterator

from . import audit_client
from . import classifier as _cls


AIOSH_CONSTITUTION_PATH = os.environ.get(
    "AIOSH_CONSTITUTION",
    "/content/AIOS_MERGED/mostimportanAIfolder/AI_CONSTITUTION.md",
)


def active_constitution_rev(path: str | None = None) -> str:
    """Mirror of `code/aiosh-cli/src/constitution.ts:readConstitution()` —
    the first 12 hex chars of sha256 of the active Constitution file.
    If the file is missing, returns the implicit 'v0.0' so that the audit
    row makes the absence explicit, never silent."""
    p = path or AIOSH_CONSTITUTION_PATH
    try:
        with open(p, "rb") as f:
            import hashlib
            return hashlib.sha256(f.read()).hexdigest()[:12]
    except FileNotFoundError:
        return "v0.0"


@contextmanager
def conn_ctx() -> Iterator[Any]:
    conn = audit_client.open_db()
    try:
        yield conn
    finally:
        conn.close()


def _classify_dict(
    tool: str, target: str | None, args: dict[str, Any],
) -> dict[str, Any]:
    """Run the Sprint-1.5 rule-pack classifier and return its
    ClassificationResult as a dict (via .to_dict()). The dispatch
    gate persists every field of this result in the audit row so
    the chain proves which rule revision decided each tool call
    (per ADR-0035 §D-4)."""
    return _cls.classify(tool, target, args).to_dict()


def _classify_to_c_flags(result: dict[str, Any]) -> dict[str, bool]:
    """Extract the c_flags booleans from a ClassificationResult dict
    for the c1..c4 audit columns. We still write the full classifier
    result into the new Sprint-2 columns; the c1..c4 columns stay for
    backward-compatible smoke assertions and SQL filters."""
    cf = result["c_flags"]
    return {
        "c1": bool(cf["c1"]["flag"]),
        "c2": bool(cf["c2"]["flag"]),
        "c3": bool(cf["c3"]["flag"]),
        "c4": bool(cf["c4"]["flag"]),
    }


def _classify_evidence(
    result: dict[str, Any],
) -> dict[str, list[str]]:
    """Evidence per C-flag (verbatim from the rule pack)."""
    cf = result["c_flags"]
    return {
        "c1": list(cf["c1"]["evidence"]),
        "c2": list(cf["c2"]["evidence"]),
        "c3": list(cf["c3"]["evidence"]),
        "c4": list(cf["c4"]["evidence"]),
    }


def dispatch(
    *,
    tool: str,
    command: str,
    args: dict[str, Any],
    target: str | None,
    grant_id: str | None,
    require_grant: bool = False,
    actor_id: str = "agent:mcp@aiosh-mcp",
    actor: str = "agent",
) -> tuple[dict[str, Any], audit_client.AuditRow]:
    """Run the gate, append one audit row, return (verdict, row).

    Gate ordering (per ADR-0035 §D-4):
      1. Rule-pack classifier verdict — fires first. If overall_verdict
         is "refused", we refuse regardless of grant presence. This is
         the safety boundary: even a perfectly-scoped grant cannot
         authorize an action the rule pack classifies as refused.
      2. PEP grant check — if classifier passes, the grant must also
         authorize the (tool, target, args).

    The classifier result is persisted verbatim in the audit row, so
    the chain proves which rule revision decided each action. The
    agent loop reads `audit_id` from the returned row to cross-link
    agent step N's reasoning with audit row N (and any subsequent
    tool-result rows)."""
    cls_result = _classify_dict(tool, target, args)
    cls_c_flags = _classify_to_c_flags(cls_result)
    cls_evidence = _classify_evidence(cls_result)
    cls_rule_ids = list(cls_result.get("rule_ids") or [])
    cls_overall = cls_result.get("overall_verdict", "ok")
    cls_reason = cls_result.get("verdict_reason", "")
    cls_policy = cls_result.get("policy_revision", _cls.CLASSIFIER_REVISION)

    # Gate #1 — classifier.
    if cls_overall == "refused":
        reason = (
            f"classifier refused (policy={cls_policy}, "
            f"verdict={cls_reason or 'refused'})"
        )
        with conn_ctx() as conn:
            row = audit_client.write_audit_row(conn, {
                "ts": audit_client.utcnow_iso(),
                "actor": actor,
                "actor_id": actor_id,
                "tool": tool,
                "command": command,
                "args": args,
                "target": target,
                "outcome": "refused",
                "outcome_detail": reason,
                "constitution_rev": active_constitution_rev(),
                "grant_token": grant_id,
                "c_flags": cls_c_flags,
                "policy_revision": cls_policy,
                "classify_rule_ids": cls_rule_ids,
                "classify_evidence": cls_evidence,
                "classify_overall_verdict": cls_overall,
                "classify_verdict_reason": cls_reason,
            })
        return ({"ok": False, "tool": tool,
                 "audit_id": row.id, "reason": reason,
                 "gate": "classifier", "policy_revision": cls_policy}, row)

    # Gate #2 — PEP grant. Some read-only tools (notably fs.read's
    # legacy safe-root policy) explicitly require a grant even though
    # the generic irreversible classifier does not. Keep that policy
    # explicit at the dispatch boundary rather than in an un-audited
    # wrapper.
    with conn_ctx() as conn:
        verdict = audit_client.grant_check(conn, grant_id, tool, target)
        if require_grant and grant_id is None:
            verdict = {"ok": False,
                       "reason": f"tool '{tool}' requires explicit PEP grant"}
        if not verdict["ok"]:
            row = audit_client.write_audit_row(conn, {
                "ts": audit_client.utcnow_iso(),
                "actor": actor,
                "actor_id": actor_id,
                "tool": tool,
                "command": command,
                "args": args,
                "target": target,
                "outcome": "refused",
                "outcome_detail": verdict["reason"],
                "constitution_rev": active_constitution_rev(),
                "grant_token": grant_id,
                "c_flags": cls_c_flags,
                "policy_revision": cls_policy,
                "classify_rule_ids": cls_rule_ids,
                "classify_evidence": cls_evidence,
                "classify_overall_verdict": cls_overall,
                "classify_verdict_reason": cls_reason,
            })
            return ({"ok": False, "tool": tool,
                     "audit_id": row.id, "reason": verdict["reason"],
                     "gate": "pep", "policy_revision": cls_policy}, row)

        # Gate #2.5 — Invariant I-2: Redeem-Before-Act Gate
        if grant_id is not None:
            redeem_res = audit_client.grant_redeem(
                conn,
                grant_id=grant_id,
                actor=actor,
                actor_id=actor_id,
                tool=tool,
                command=command,
                args=args,
                target=target,
            )
            if not redeem_res["ok"]:
                row = audit_client.write_audit_row(conn, {
                    "ts": audit_client.utcnow_iso(),
                    "actor": actor,
                    "actor_id": actor_id,
                    "tool": tool,
                    "command": command,
                    "args": args,
                    "target": target,
                    "outcome": "refused",
                    "outcome_detail": redeem_res["reason"],
                    "constitution_rev": active_constitution_rev(),
                    "grant_token": grant_id,
                    "c_flags": cls_c_flags,
                    "policy_revision": cls_policy,
                    "classify_rule_ids": cls_rule_ids,
                    "classify_evidence": cls_evidence,
                    "classify_overall_verdict": cls_overall,
                    "classify_verdict_reason": cls_reason,
                })
                return ({"ok": False, "tool": tool,
                         "audit_id": row.id, "reason": redeem_res["reason"],
                         "gate": "pep.redeem", "policy_revision": cls_policy}, row)
    # Gate passed: caller still writes the success/error row inside its
    # own try/except via commit(...). The classification_result is also
    # returned for the caller's audit-row write path to mirror.
    return ({"ok": True, "tool": tool,
             "policy_revision": cls_policy,
             "classify_rule_ids": cls_rule_ids,
             "classify_evidence": cls_evidence,
             "classify_overall_verdict": cls_overall,
             "classify_verdict_reason": cls_reason,
             "c_flags": cls_c_flags}, None)


def commit(
    *,
    tool: str,
    command: str,
    args: dict[str, Any],
    target: str | None,
    grant_id: str | None,
    outcome: str,
    outcome_detail: str | None,
    actor_id: str = "agent:mcp@aiosh-mcp",
    actor: str = "agent",
    policy_revision: str | None = None,
    classify_rule_ids: list[str] | None = None,
    classify_evidence: dict[str, list[str]] | None = None,
    classify_overall_verdict: str | None = None,
    classify_verdict_reason: str | None = None,
) -> audit_client.AuditRow:
    """Append the actual outcome row (ok | error) after a gate-passed call.

    The classifier-decision fields are passed through from the dispatch()
    pre-check so every tool-result audit row carries the same provenance
    as the refused/pre-check row would have. If any classifier field is
    missing, we re-classify once and fill in the gaps — the audit row is
    never silent on which rule decided it (per ADR-0035 §D-4).
    """
    if (policy_revision is None or classify_overall_verdict is None
            or classify_evidence is None or classify_rule_ids is None):
        fresh = _classify_dict(tool, target, args)
        if policy_revision is None:
            policy_revision = fresh.get(
                "policy_revision", _cls.CLASSIFIER_REVISION)
        if classify_rule_ids is None:
            classify_rule_ids = list(fresh.get("rule_ids") or [])
        if classify_evidence is None:
            classify_evidence = _classify_evidence(fresh)
        if classify_overall_verdict is None:
            classify_overall_verdict = fresh.get("overall_verdict", "ok")
        if classify_verdict_reason is None:
            classify_verdict_reason = fresh.get("verdict_reason", "")
    c_flags = _classify_to_c_flags(_classify_dict(tool, target, args))
    with conn_ctx() as conn:
        return audit_client.write_audit_row(conn, {
            "ts": audit_client.utcnow_iso(),
            "actor": actor,
            "actor_id": actor_id,
            "tool": tool,
            "command": command,
            "args": args,
            "target": target,
            "outcome": outcome,
            "outcome_detail": outcome_detail,
            "constitution_rev": active_constitution_rev(),
            "grant_token": grant_id,
            "c_flags": c_flags,
            "policy_revision": policy_revision,
            "classify_rule_ids": classify_rule_ids,
            "classify_evidence": classify_evidence,
            "classify_overall_verdict": classify_overall_verdict,
            "classify_verdict_reason": classify_verdict_reason,
        })


def run_subprocess(
    argv: list[str],
    *,
    timeout_s: int = 60,
    stdin_payload: bytes | None = None,
) -> dict[str, Any]:
    """Run a CLI tool safely. Output capped so a hostile tool cannot
    return megabytes to the agent context."""
    import subprocess
    cap = 16 * 1024
    errcap = 4 * 1024
    try:
        proc = subprocess.run(
            argv,
            input=stdin_payload,
            capture_output=True,
            text=False,
            timeout=timeout_s,
            check=False,
        )
        return {
            "ok": proc.returncode == 0,
            "rc": proc.returncode,
            "stdout": proc.stdout[:cap].decode("utf-8", errors="replace")
                      if proc.stdout else "",
            "stderr": proc.stderr[:errcap].decode("utf-8", errors="replace")
                      if proc.stderr else "",
            "stdout_truncated": bool(proc.stdout) and len(proc.stdout) > cap,
            "stderr_truncated": bool(proc.stderr) and len(proc.stderr) > errcap,
            "argv": argv,
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timeout after {timeout_s}s",
                "argv": argv}
    except FileNotFoundError as e:
        return {"ok": False, "error": f"binary not on PATH: {e.filename}",
                "argv": argv}


def host_has(binary: str) -> str | None:
    """Return absolute path of `binary` if on PATH, else None.
    We don't depend on shutil.which so the helper stays stdlib-only."""
    import os
    for d in os.environ.get("PATH", "").split(":"):
        if not d:
            continue
        cand = os.path.join(d, binary)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None
