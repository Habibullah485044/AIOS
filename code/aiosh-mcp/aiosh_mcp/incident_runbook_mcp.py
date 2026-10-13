"""Incident Response Runbooks & RustSec Scanning MCP Surface (T-02995 Scaffold).

Provides FastMCP tool registrations and dispatch logic for `aios_runbook` and `aios_scan`.
"""

from __future__ import annotations
from typing import Any
import threading

from mcp.server.fastmcp import FastMCP

from . import _dispatch as dispatch_mod
from .incident_runbook_service import (
    RunbookExecutionSession,
    RunbookCatalogSnapshot,
)

# Active session store with lock for thread safety
_SESSION_STORE_LOCK = threading.Lock()
_ACTIVE_SESSIONS: dict[str, RunbookExecutionSession] = {}


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
    """Dispatch runbook action across catalog and active sessions.
    Scaffold implementation raises NotImplementedError for unimplemented logic.
    """
    raise NotImplementedError("execute_runbook_action scaffold - pending T-02996 implementation")


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
    """Dispatch security scan action (net, files, web).
    Scaffold implementation raises NotImplementedError for unimplemented logic.
    """
    raise NotImplementedError("execute_scan_action scaffold - pending T-02996 implementation")


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
        Actions: list | show | init | start | step | confirm | status | abort.
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
