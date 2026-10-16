"""Incident Response Runbooks & RustSec Scanning MCP Surface (T-02996 Implementation).

Provides FastMCP tool registrations and authoritative dispatch logic for:
  - `aios_runbook`: lifecycle management of incident containment and eradication runbooks.
  - `aios_scan`: RustSec security scanning substrate (ports, files, web endpoints).
"""

from __future__ import annotations
from typing import Any
import os
import re
import socket
import time
import threading
import urllib.request
import urllib.error

from mcp.server.fastmcp import FastMCP

from . import _dispatch as dispatch_mod
from .incident_runbook_data_model import (
    RunbookCatalogSnapshot,
    IncidentCategory,
    IncidentSeverity,
    RUNBOOK_ERR_BOUNDS_EXCEEDED,
    RUNBOOK_ERR_INVALID_TEMPLATE,
)
from .incident_runbook_service import (
    RunbookExecutionSession,
    RunbookExecutionStatus,
    StepExecutionStatus,
    RUNBOOK_ERR_SESSION_NOT_FOUND,
    RUNBOOK_ERR_INVALID_TRANSITION,
    RUNBOOK_ERR_MISSING_CONFIRMATION,
    RUNBOOK_ERR_INVALID_PARAM_VALUE,
    MAX_RUNBOOK_PARAM_LEN,
    MAX_RUNBOOK_PARAMS_COUNT,
    validate_parameter_value,
)

from .runbook_config import resolve_runbook_config
from .incident_runbook_policy import RunbookSecurityPolicy
from .incident_runbook_observability import RunbookObservabilityService
from .incident_runbook_doc import (
    RunbookDocRepository,
    RunbookDocCategory,
    IRDOC_ERR_NOT_FOUND,
    IRDOC_ERR_QUERY_BOUNDS,
)


# Constants & Bounds Clamping
MAX_SCAN_TARGET_LEN = 256
MAX_PORTS_PER_SCAN = 10000
MAX_FILE_SCAN_DEPTH = 32
MAX_FILE_SCAN_SIZE = 16 * 1024 * 1024  # 16 MiB
MAX_FILE_MATCHES = 1000
MAX_WEB_PATHS = 1000

SEC_ERR_INVALID_TARGET = "SEC_ERR_INVALID_TARGET"
SEC_ERR_BOUNDS_EXCEEDED = "SEC_ERR_BOUNDS_EXCEEDED"

RUNBOOK_READ_ACTIONS = {"list", "show", "status", "config", "policy", "stats", "doc_list", "doc_get", "doc_search"}
RUNBOOK_WRITE_ACTIONS = {"start", "step", "confirm", "abort", "init"}
SCAN_ACTIONS = {"net", "files", "web"}

_RUNBOOK_DOC_REPO = RunbookDocRepository()

# Active session store with lock for thread safety
_SESSION_STORE_LOCK = threading.Lock()
_ACTIVE_SESSIONS: dict[str, RunbookExecutionSession] = {}
_CATALOG_SNAPSHOT = RunbookCatalogSnapshot.canonical_baseline()
_ACTIVE_POLICY = RunbookSecurityPolicy()


def validate_scan_target(target: str) -> str:
    """Validate scan target string against path traversal, control chars, and whitelist."""
    trimmed = target.strip()
    if not trimmed:
        raise ValueError(f"{SEC_ERR_INVALID_TARGET}: Target cannot be empty")
    if len(trimmed) > MAX_SCAN_TARGET_LEN:
        raise ValueError(f"{SEC_ERR_BOUNDS_EXCEEDED}: Target length {len(trimmed)} exceeds maximum {MAX_SCAN_TARGET_LEN}")
    if ".." in trimmed:
        raise ValueError(f"{SEC_ERR_INVALID_TARGET}: Path traversal '..' strictly prohibited")
    if "\0" in trimmed or "\n" in trimmed or "\r" in trimmed:
        raise ValueError(f"{SEC_ERR_INVALID_TARGET}: Control characters strictly prohibited")
    if not re.match(r"^[a-zA-Z0-9_\-\.:/\\~@]+$", trimmed):
        raise ValueError(f"{SEC_ERR_INVALID_TARGET}: Target contains illegal characters outside whitelist")
    return trimmed


def _recorded_mcp_call(
    *,
    tool: str,
    command: str,
    args: dict[str, Any],
    target: str | None,
    grant_id: str | None,
    fn: Any,
    require_grant: bool = False,
) -> dict[str, Any]:
    """Execute callable behind authoritative dispatch gate and append audit row."""
    verdict, _ = dispatch_mod.dispatch(
        tool=tool,
        command=command,
        args=args,
        target=target,
        grant_id=grant_id,
        require_grant=require_grant,
    )
    if not verdict["ok"]:
        return verdict

    try:
        raw = fn()
        if not isinstance(raw, dict):
            raw = {"ok": True, "result": raw}
        outcome = "ok" if raw.get("ok", True) else "error"
        detail = None if outcome == "ok" else str(raw.get("error", "tool returned ok=false"))
        row = dispatch_mod.commit(
            tool=tool,
            command=command,
            args=args,
            target=target,
            grant_id=grant_id,
            outcome=outcome,
            outcome_detail=detail,
            policy_revision=verdict.get("policy_revision"),
            classify_rule_ids=verdict.get("classify_rule_ids"),
            classify_evidence=verdict.get("classify_evidence"),
            classify_overall_verdict=verdict.get("classify_overall_verdict"),
            classify_verdict_reason=verdict.get("classify_verdict_reason"),
        )
        raw["audit_id"] = row.id
        return raw
    except Exception as exc:
        detail = str(exc)
        row = dispatch_mod.commit(
            tool=tool,
            command=command,
            args=args,
            target=target,
            grant_id=grant_id,
            outcome="error",
            outcome_detail=detail,
            policy_revision=verdict.get("policy_revision"),
            classify_rule_ids=verdict.get("classify_rule_ids"),
            classify_evidence=verdict.get("classify_evidence"),
            classify_overall_verdict=verdict.get("classify_overall_verdict"),
            classify_verdict_reason=verdict.get("classify_verdict_reason"),
        )
        action_name = command.split(".")[-1] if "." in command else command
        return {"ok": False, "action": action_name, "error": detail, "audit_id": row.id}


def execute_runbook_core(
    action: str,
    runbook_id: str | None = None,
    session_id: str | None = None,
    incident_id: str | None = None,
    parameters: dict[str, str] | None = None,
    category: str | None = None,
    severity: str | None = None,
    operator_id: str | None = None,
    token: str | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    global _CATALOG_SNAPSHOT

    if action == "list":
        cat_enum = IncidentCategory(category) if category else None
        sev_enum = IncidentSeverity(severity) if severity else None
        specs = [
            r for r in _CATALOG_SNAPSHOT.runbooks
            if (not cat_enum or r.category == cat_enum)
            and (not sev_enum or r.severity == sev_enum)
        ]
        return {
            "ok": True,
            "action": "list",
            "runbooks": [
                {
                    "id": s.id,
                    "title": s.title,
                    "category": s.category.value,
                    "severity": s.severity.value,
                    "steps_count": len(s.steps),
                }
                for s in specs
            ],
        }

    if action == "show":
        if not runbook_id:
            raise ValueError(f"{RUNBOOK_ERR_SESSION_NOT_FOUND}: runbook_id is required for show")
        spec = _CATALOG_SNAPSHOT.get_runbook(runbook_id)
        if not spec:
            raise ValueError(f"{RUNBOOK_ERR_SESSION_NOT_FOUND}: Runbook '{runbook_id}' not found")
        return {
            "ok": True,
            "action": "show",
            "runbook": {
                "id": spec.id,
                "title": spec.title,
                "category": spec.category.value,
                "severity": spec.severity.value,
                "description": spec.description,
                "tags": spec.tags,
                "steps": [
                    {
                        "id": st.id,
                        "title": st.title,
                        "phase": st.phase.value,
                        "target": st.target.value,
                        "action_template": st.action_template,
                        "automated": st.automated,
                        "requires_confirmation": st.requires_confirmation,
                        "timeout_seconds": st.timeout_seconds,
                    }
                    for st in spec.steps
                ],
            },
        }

    if action == "config":
        c_path = parameters.get("config_path") if parameters else None
        cfg = resolve_runbook_config(config_path=c_path)
        return {
            "ok": True,
            "action": "config",
            "config": cfg.to_dict(),
        }

    if action == "policy":
        return {
            "ok": True,
            "action": "policy",
            "version": _ACTIVE_POLICY.version,
            "mode": _ACTIVE_POLICY.mode.value,
            "require_operator_confirmation_for_high_risk": _ACTIVE_POLICY.require_operator_confirmation_for_high_risk,
            "max_step_timeout_seconds": _ACTIVE_POLICY.max_step_timeout_seconds,
            "max_active_sessions": _ACTIVE_POLICY.max_active_sessions,
            "require_pep_grant": _ACTIVE_POLICY.require_pep_grant,
        }

    if action == "stats":
        with _SESSION_STORE_LOCK:
            active_copy = dict(_ACTIVE_SESSIONS)
        envelope = RunbookObservabilityService.generate_snapshot_safe(
            catalog=_CATALOG_SNAPSHOT,
            active_sessions=active_copy,
            policy=_ACTIVE_POLICY,
        )
        if not envelope.ok:
            return {
                "ok": False,
                "action": "stats",
                "error": envelope.error_message,
                "error_code": envelope.error_code,
                "audit_row_required": envelope.audit_row_required,
            }
        return {
            "ok": True,
            "action": "stats",
            "stats": envelope.snapshot.to_dict() if envelope.snapshot else {},
            "audit_row_required": envelope.audit_row_required,
        }

    if action == "doc_list":
        cat_filter = None
        if category:
            try:
                cat_filter = RunbookDocCategory(category)
            except ValueError:
                pass
        topics = _RUNBOOK_DOC_REPO.list_by_category(cat_filter) if cat_filter else _RUNBOOK_DOC_REPO.list_topics()
        return {
            "ok": True,
            "action": "doc_list",
            "topics": [
                {
                    "id": t.id,
                    "title": t.title,
                    "category": t.category.value,
                    "summary": t.summary,
                    "related_topics": t.related_topics,
                }
                for t in topics
            ],
        }

    if action == "doc_get":
        target_id = runbook_id or (parameters.get("id") if parameters else None)
        if not target_id:
            raise ValueError(f"{IRDOC_ERR_NOT_FOUND}: topic id is required")
        topic = _RUNBOOK_DOC_REPO.get_topic(target_id)
        if not topic:
            raise ValueError(f"{IRDOC_ERR_NOT_FOUND}: topic '{target_id}' not found")
        return {
            "ok": True,
            "action": "doc_get",
            "topic": {
                "id": topic.id,
                "title": topic.title,
                "category": topic.category.value,
                "summary": topic.summary,
                "sections": [{"title": s.title, "content": s.content} for s in topic.sections],
                "related_topics": topic.related_topics,
                "markdown": topic.to_markdown(),
            },
        }

    if action == "doc_search":
        q = (parameters.get("query") if parameters else None) or reason or ""
        cat_filter = None
        if category:
            try:
                cat_filter = RunbookDocCategory(category)
            except ValueError:
                pass
        results = _RUNBOOK_DOC_REPO.search(q, category=cat_filter)
        return {
            "ok": True,
            "action": "doc_search",
            "query": q,
            "results": [
                {
                    "topic_id": r.topic_id,
                    "title": r.title,
                    "category": r.category.value,
                    "score": r.score,
                    "snippet": r.snippet,
                }
                for r in results
            ],
        }

    if action == "init":
        _CATALOG_SNAPSHOT = RunbookCatalogSnapshot.canonical_baseline()
        return {
            "ok": True,
            "action": "init",
            "catalog_version": _CATALOG_SNAPSHOT.catalog_version,
            "runbooks_count": len(_CATALOG_SNAPSHOT.runbooks),
        }

    if action == "start":
        if not runbook_id:
            raise ValueError(f"{RUNBOOK_ERR_SESSION_NOT_FOUND}: runbook_id is required for start")
        if not incident_id:
            raise ValueError(f"{RUNBOOK_ERR_SESSION_NOT_FOUND}: incident_id is required for start")
        spec = _CATALOG_SNAPSHOT.get_runbook(runbook_id)
        if not spec:
            raise ValueError(f"{RUNBOOK_ERR_SESSION_NOT_FOUND}: Runbook '{runbook_id}' not found")

        _ACTIVE_POLICY.evaluate_runbook_start(spec)

        params = parameters or {}
        if len(params) > MAX_RUNBOOK_PARAMS_COUNT:
            raise ValueError(f"{RUNBOOK_ERR_BOUNDS_EXCEEDED}: Parameters count {len(params)} exceeds maximum {MAX_RUNBOOK_PARAMS_COUNT}")
        for k, v in params.items():
            validate_parameter_value(k, str(v))

        session = RunbookExecutionSession.init_from_spec(spec, incident_id, params)
        cfg = resolve_runbook_config()
        with _SESSION_STORE_LOCK:
            if len(_ACTIVE_SESSIONS) >= cfg.max_active_sessions:
                oldest = next(iter(_ACTIVE_SESSIONS))
                _ACTIVE_SESSIONS.pop(oldest, None)
            _ACTIVE_SESSIONS[session.session_id] = session

        return {
            "ok": True,
            "action": "start",
            "session_id": session.session_id,
            "runbook_id": runbook_id,
            "incident_id": incident_id,
            "status": session.status.value,
            "current_step_index": session.current_step_index,
            "total_steps": len(spec.steps),
        }

    if action == "step":
        if not session_id:
            raise ValueError(f"{RUNBOOK_ERR_SESSION_NOT_FOUND}: session_id is required for step")
        with _SESSION_STORE_LOCK:
            session = _ACTIVE_SESSIONS.get(session_id)
        if not session:
            raise ValueError(f"{RUNBOOK_ERR_SESSION_NOT_FOUND}: Session '{session_id}' not found")

        spec = _CATALOG_SNAPSHOT.get_runbook(session.runbook_id)
        if not spec:
            raise ValueError(f"{RUNBOOK_ERR_SESSION_NOT_FOUND}: Runbook spec '{session.runbook_id}' missing")

        if session.is_terminal():
            raise ValueError(f"{RUNBOOK_ERR_INVALID_TRANSITION}: Session '{session_id}' is already terminal ({session.status.value})")

        st = session.advance_step(spec, simulate_success=True)
        if st == StepExecutionStatus.AWAITING_CONFIRMATION:
            return {
                "ok": False,
                "action": "step",
                "error": f"{RUNBOOK_ERR_MISSING_CONFIRMATION}: Step requires operator confirmation before advancing",
                "session_id": session_id,
                "step_index": session.current_step_index,
                "awaiting_confirmation": True,
            }

        return {
            "ok": True,
            "action": "step",
            "session_id": session_id,
            "step_status": st.value,
            "status": session.status.value,
            "current_step_index": session.current_step_index,
            "total_steps": len(spec.steps),
        }

    if action == "confirm":
        if not session_id:
            raise ValueError(f"{RUNBOOK_ERR_SESSION_NOT_FOUND}: session_id is required for confirm")
        if not operator_id or not operator_id.strip() or len(operator_id) > 64:
            raise ValueError(f"{RUNBOOK_ERR_MISSING_CONFIRMATION}: operator_id must be non-empty and <= 64 characters")
        if not token or not token.strip() or len(token) > 64:
            raise ValueError(f"{RUNBOOK_ERR_MISSING_CONFIRMATION}: token must be non-empty and <= 64 characters")

        with _SESSION_STORE_LOCK:
            session = _ACTIVE_SESSIONS.get(session_id)
        if not session:
            raise ValueError(f"{RUNBOOK_ERR_SESSION_NOT_FOUND}: Session '{session_id}' not found")

        session.confirm_current_step(operator_id, token)
        return {
            "ok": True,
            "action": "confirm",
            "session_id": session_id,
            "confirmed_by": operator_id,
            "status": session.status.value,
        }

    if action == "status":
        if not session_id:
            raise ValueError(f"{RUNBOOK_ERR_SESSION_NOT_FOUND}: session_id is required for status")
        with _SESSION_STORE_LOCK:
            session = _ACTIVE_SESSIONS.get(session_id)
        if not session:
            raise ValueError(f"{RUNBOOK_ERR_SESSION_NOT_FOUND}: Session '{session_id}' not found")

        return {
            "ok": True,
            "action": "status",
            "session": {
                "session_id": session.session_id,
                "runbook_id": session.runbook_id,
                "incident_id": session.incident_id,
                "status": session.status.value,
                "current_step_index": session.current_step_index,
                "parameters": session.parameters,
                "started_at": session.started_at,
                "completed_at": session.completed_at,
                "steps_completed": len([r for r in session.step_records if r.status == StepExecutionStatus.COMPLETED]),
            },
        }

    if action == "abort":
        if not session_id:
            raise ValueError(f"{RUNBOOK_ERR_SESSION_NOT_FOUND}: session_id is required for abort")
        with _SESSION_STORE_LOCK:
            session = _ACTIVE_SESSIONS.get(session_id)
        if not session:
            raise ValueError(f"{RUNBOOK_ERR_SESSION_NOT_FOUND}: Session '{session_id}' not found")

        session.abort(reason=reason or "Operator requested abort")
        return {
            "ok": True,
            "action": "abort",
            "session_id": session_id,
            "status": session.status.value,
        }

    raise ValueError(f"Unknown action: '{action}'")


def execute_scan_core(
    action: str,
    target: str,
    ports: str | None = None,
    pattern: str | None = None,
    wordlist: str | None = None,
    timeout_ms: int | None = None,
    max_depth: int | None = None,
    max_size: int | None = None,
) -> dict[str, Any]:
    validated_target = validate_scan_target(target)
    start_time = time.monotonic()

    _ACTIVE_POLICY.evaluate_scan_operation(
        action=action,
        ports_count=len(ports.split(",")) if ports else 4,
        depth=max_depth or 5,
    )

    if action == "net":
        ports_list = []
        if ports:
            for part in ports.split(","):
                part = part.strip()
                if "-" in part:
                    p1, p2 = part.split("-", 1)
                    ports_list.extend(range(int(p1), int(p2) + 1))
                elif part:
                    ports_list.append(int(part))
        else:
            ports_list = [22, 80, 443, 8080]

        if len(ports_list) > MAX_PORTS_PER_SCAN:
            ports_list = ports_list[:MAX_PORTS_PER_SCAN]

        t_ms = max(10, min(10000, timeout_ms or 100))
        t_sec = t_ms / 1000.0

        open_ports = []
        for p in ports_list:
            if not (1 <= p <= 65535):
                continue
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(t_sec)
            try:
                res = sock.connect_ex((validated_target, p))
                if res == 0:
                    open_ports.append(p)
            except Exception:
                pass
            finally:
                sock.close()

        elapsed = int((time.monotonic() - start_time) * 1000)
        return {
            "ok": True,
            "action": "net",
            "target": validated_target,
            "open_ports": open_ports,
            "scanned_ports_count": len(ports_list),
            "elapsed_ms": elapsed,
        }

    if action == "files":
        if not pattern:
            raise ValueError(f"{SEC_ERR_INVALID_TARGET}: pattern is required for file search")
        regex = re.compile(pattern)
        depth_limit = max(1, min(MAX_FILE_SCAN_DEPTH, max_depth or 16))
        size_limit = max(1, min(MAX_FILE_SCAN_SIZE, max_size or 1024 * 1024))

        matches = []
        target_path = os.path.abspath(validated_target)
        if not os.path.exists(target_path):
            raise ValueError(f"{SEC_ERR_INVALID_TARGET}: Target path '{target_path}' does not exist")

        base_depth = target_path.count(os.sep)
        for root, dirs, files in os.walk(target_path):
            current_depth = root.count(os.sep) - base_depth
            if current_depth > depth_limit:
                dirs.clear()
                continue

            for f in files:
                file_path = os.path.join(root, f)
                try:
                    st = os.stat(file_path)
                    if st.st_size > size_limit:
                        continue
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                        for line_no, line in enumerate(fh, start=1):
                            if regex.search(line):
                                matches.append({
                                    "file": file_path,
                                    "line_no": line_no,
                                    "line": line.strip()[:200],
                                })
                                if len(matches) >= MAX_FILE_MATCHES:
                                    break
                except Exception:
                    continue
                if len(matches) >= MAX_FILE_MATCHES:
                    break
            if len(matches) >= MAX_FILE_MATCHES:
                break

        elapsed = int((time.monotonic() - start_time) * 1000)
        return {
            "ok": True,
            "action": "files",
            "target": validated_target,
            "pattern": pattern,
            "matches": matches,
            "matches_count": len(matches),
            "elapsed_ms": elapsed,
        }

    if action == "web":
        paths = [p.strip() for p in (wordlist or "admin,login,api,metrics").split(",") if p.strip()]
        if len(paths) > MAX_WEB_PATHS:
            paths = paths[:MAX_WEB_PATHS]

        t_ms = max(50, min(10000, timeout_ms or 500))
        t_sec = t_ms / 1000.0

        base_url = validated_target.rstrip("/")
        if not base_url.startswith("http://") and not base_url.startswith("https://"):
            base_url = f"http://{base_url}"

        discovered = []
        for p in paths:
            probe_path = p.lstrip("/")
            full_url = f"{base_url}/{probe_path}"
            req = urllib.request.Request(full_url, headers={"User-Agent": "aiosh-sec/1.0"})
            try:
                with urllib.request.urlopen(req, timeout=t_sec) as resp:
                    discovered.append({
                        "path": f"/{probe_path}",
                        "status_code": resp.status,
                    })
            except urllib.error.HTTPError as exc:
                if exc.code in (401, 403, 500):
                    discovered.append({
                        "path": f"/{probe_path}",
                        "status_code": exc.code,
                    })
            except Exception:
                pass

        elapsed = int((time.monotonic() - start_time) * 1000)
        return {
            "ok": True,
            "action": "web",
            "target": validated_target,
            "discovered_endpoints": discovered,
            "probed_count": len(paths),
            "elapsed_ms": elapsed,
        }

    raise ValueError(f"Unknown action: '{action}'")


def execute_runbook_action(
    action: str,
    runbook_id: str | None = None,
    session_id: str | None = None,
    incident_id: str | None = None,
    parameters: dict[str, str] | None = None,
    category: str | None = None,
    severity: str | None = None,
    operator_id: str | None = None,
    token: str | None = None,
    reason: str | None = None,
    grant_id: str | None = None,
) -> dict[str, Any]:
    """Dispatch runbook action behind authoritative audit and PEP gate."""
    args = {
        "action": action,
        "runbook_id": runbook_id,
        "session_id": session_id,
        "incident_id": incident_id,
        "parameters": parameters,
        "category": category,
        "severity": severity,
        "operator_id": operator_id,
        "token": token,
        "reason": reason,
    }
    clean_args = {k: v for k, v in args.items() if v is not None}

    def run():
        return execute_runbook_core(
            action=action,
            runbook_id=runbook_id,
            session_id=session_id,
            incident_id=incident_id,
            parameters=parameters,
            category=category,
            severity=severity,
            operator_id=operator_id,
            token=token,
            reason=reason,
        )

    return _recorded_mcp_call(
        tool="aios.runbook",
        command=f"runbook.{action}",
        args=clean_args,
        target=runbook_id or session_id,
        grant_id=grant_id,
        fn=run,
        require_grant=action in RUNBOOK_WRITE_ACTIONS and grant_id is not None,
    )


def execute_scan_action(
    action: str,
    target: str,
    ports: str | None = None,
    pattern: str | None = None,
    wordlist: str | None = None,
    timeout_ms: int | None = None,
    max_depth: int | None = None,
    max_size: int | None = None,
    grant_id: str | None = None,
) -> dict[str, Any]:
    """Dispatch security scan action (net, files, web) behind audit gate."""
    clean_args = {
        "action": action,
        "target": target,
        "ports": ports,
        "pattern": pattern,
        "wordlist": wordlist,
        "timeout_ms": timeout_ms,
        "max_depth": max_depth,
        "max_size": max_size,
    }
    clean_args = {k: v for k, v in clean_args.items() if v is not None}

    def run():
        return execute_scan_core(
            action=action,
            target=target,
            ports=ports,
            pattern=pattern,
            wordlist=wordlist,
            timeout_ms=timeout_ms,
            max_depth=max_depth,
            max_size=max_size,
        )

    return _recorded_mcp_call(
        tool="aios.scan",
        command=f"scan.{action}",
        args=clean_args,
        target=target,
        grant_id=grant_id,
        fn=run,
        require_grant=grant_id is not None,
    )


def register_runbook_tools(mcp: FastMCP) -> None:
    """Register `aios_runbook` and `aios_scan` tools with FastMCP server."""

    @mcp.tool()
    def aios_runbook(
        action: str,
        runbook_id: str | None = None,
        session_id: str | None = None,
        incident_id: str | None = None,
        parameters: dict[str, str] | None = None,
        category: str | None = None,
        severity: str | None = None,
        operator_id: str | None = None,
        token: str | None = None,
        reason: str | None = None,
        grant_id: str | None = None,
    ) -> dict[str, Any]:
        """Incident Response Runbooks control surface (SPEC-INCIDENT-RUNBOOK-MCP):
        Actions: list | show | init | start | step | confirm | status | abort | config | policy | stats.
        """
        return execute_runbook_action(
            action=action,
            runbook_id=runbook_id,
            session_id=session_id,
            incident_id=incident_id,
            parameters=parameters,
            category=category,
            severity=severity,
            operator_id=operator_id,
            token=token,
            reason=reason,
            grant_id=grant_id,
        )

    @mcp.tool()
    def aios_scan(
        action: str,
        target: str,
        ports: str | None = None,
        pattern: str | None = None,
        wordlist: str | None = None,
        timeout_ms: int | None = None,
        max_depth: int | None = None,
        max_size: int | None = None,
        grant_id: str | None = None,
    ) -> dict[str, Any]:
        """RustSec security scanning substrate (SPEC-INCIDENT-RUNBOOK-MCP):
        Actions: net | files | web.
        """
        return execute_scan_action(
            action=action,
            target=target,
            ports=ports,
            pattern=pattern,
            wordlist=wordlist,
            timeout_ms=timeout_ms,
            max_depth=max_depth,
            max_size=max_size,
            grant_id=grant_id,
        )
