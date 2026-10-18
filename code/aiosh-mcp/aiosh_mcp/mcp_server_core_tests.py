"""AI Control Plane MCP Server Core Automated Tests Subsystem (T-03115 scaffold / T-03116 impl).

Defines test case data models, test suite report envelopes, and runner interfaces
in compliance with SPEC-MCP-SERVER-CORE-TESTS and PoR Invariant I-2.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from .mcp_server_core_data_model import (
    McpToolDefinition,
    McpToolCall,
    McpToolResult,
    McpSessionInfo,
    McpCoreResultEnvelope,
    MAX_ARGUMENTS_SIZE,
    ERR_UNAUTHORIZED,
    ERR_METHOD_NOT_FOUND,
)
from .mcp_server_core_service import (
    McpServerCoreService,
    MCPSVC_ERR_TOOL_ALREADY_EXISTS,
    MCPSVC_ERR_SESSION_CAPACITY_EXCEEDED,
)
from .mcp_server_core_api import McpApiHandler, PROTOCOL_VERSION
from .mcp_server_core_config import (
    McpServerCoreConfig,
    McpConfigError,
    MIN_ACTIVE_SESSIONS,
    MAX_ALLOWED_ACTIVE_SESSIONS,
)


class McpTestCategory(str, Enum):
    DATA_MODEL = "data_model"
    API = "api"
    SERVICE = "service"
    CONFIG = "config"
    SECURITY = "security"


@dataclass
class McpTestCase:
    test_id: str
    category: McpTestCategory
    name: str
    passed: bool = False
    error_message: Optional[str] = None
    duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "test_id": self.test_id,
            "category": self.category.value,
            "name": self.name,
            "passed": self.passed,
            "error_message": self.error_message,
            "duration_ms": self.duration_ms,
        }


@dataclass
class McpTestSuiteReport:
    suite_name: str = "mcp_server_core_automated_tests"
    total_cases: int = 0
    passed_cases: int = 0
    failed_cases: int = 0
    duration_seconds: float = 0.0
    cases: List[McpTestCase] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return self.failed_cases == 0 and self.total_cases > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "suite_name": self.suite_name,
            "total_cases": self.total_cases,
            "passed_cases": self.passed_cases,
            "failed_cases": self.failed_cases,
            "success": self.success,
            "duration_seconds": self.duration_seconds,
            "cases": [c.to_dict() for c in self.cases],
        }

    def to_markdown(self) -> str:
        lines = [
            f"# MCP Server Core Test Suite Report: {self.suite_name}",
            f"- **Result**: {'PASS' if self.success else 'FAIL'}",
            f"- **Total**: {self.total_cases} | **Passed**: {self.passed_cases} | **Failed**: {self.failed_cases}",
            f"- **Duration**: {self.duration_seconds:.3f}s",
            "",
            "| ID | Category | Name | Status | Duration (ms) |",
            "|:---|:---|:---|:---|:---|",
        ]
        for c in self.cases:
            status = "PASS" if c.passed else f"FAIL ({c.error_message or 'unknown'})"
            lines.append(f"| {c.test_id} | {c.category.value} | {c.name} | {status} | {c.duration_ms:.2f} |")
        return "\n".join(lines)


def _execute_test(test_id: str, category: McpTestCategory, name: str, fn) -> McpTestCase:
    t0 = time.perf_counter()
    passed = False
    err_msg: Optional[str] = None
    try:
        fn()
        passed = True
    except AssertionError as exc:
        err_msg = f"Assertion failed: {exc}"
    except Exception as exc:
        err_msg = f"Exception: {type(exc).__name__}: {exc}"
    t1 = time.perf_counter()
    return McpTestCase(
        test_id=test_id,
        category=category,
        name=name,
        passed=passed,
        error_message=err_msg,
        duration_ms=(t1 - t0) * 1000.0,
    )


def _run_data_model_tests() -> List[McpTestCase]:
    cases: List[McpTestCase] = []

    def test_tool_def():
        td = McpToolDefinition(name="test_tool", description="A test tool", input_schema={})
        assert td.name == "test_tool"
        d = td.to_dict()
        assert d["name"] == "test_tool"

    cases.append(_execute_test("TEST-DATA-01", McpTestCategory.DATA_MODEL, "McpToolDefinition valid serialization", test_tool_def))

    def test_envelope():
        env = McpCoreResultEnvelope.success({"status": "ok"})
        assert env.ok is True
        assert env.to_dict()["ok"] is True
        err_env = McpCoreResultEnvelope.error(-32000, "sample error")
        assert err_env.ok is False
        assert err_env.error_code == -32000

    cases.append(_execute_test("TEST-DATA-02", McpTestCategory.DATA_MODEL, "McpCoreResultEnvelope formatting", test_envelope))
    return cases


def _run_api_tests() -> List[McpTestCase]:
    cases: List[McpTestCase] = []
    handler = McpApiHandler()

    def test_ping():
        res = handler.handle_ping(1)
        assert res["id"] == 1
        assert res["result"]["status"] == "ok"

    cases.append(_execute_test("TEST-API-01", McpTestCategory.API, "handle_ping liveness response", test_ping))

    def test_initialize():
        res = handler.handle_initialize(2, {"clientInfo": {"name": "test-client", "version": "1.0.0"}})
        assert res["id"] == 2
        assert res["result"]["protocolVersion"] == PROTOCOL_VERSION
        assert "sessionId" in res["result"]

    cases.append(_execute_test("TEST-API-02", McpTestCategory.API, "handle_initialize session setup", test_initialize))

    def test_unknown_method():
        msg = json.dumps({"jsonrpc": "2.0", "id": 99, "method": "nonexistent/method"})
        res = handler.handle_raw_message(msg)
        assert res["error"]["code"] == ERR_METHOD_NOT_FOUND

    cases.append(_execute_test("TEST-API-03", McpTestCategory.API, "Unknown method returns -32601", test_unknown_method))
    return cases


def _run_service_tests() -> List[McpTestCase]:
    cases: List[McpTestCase] = []
    svc = McpServerCoreService()

    def test_tool_registry():
        td = McpToolDefinition(name="echo", description="echo service tool", input_schema={})
        svc.register_tool(td)
        assert svc.get_tool("echo") is not None
        assert any(t.name == "echo" for t in svc.list_tools())
        assert svc.unregister_tool("echo") is True

    cases.append(_execute_test("TEST-SVC-01", McpTestCategory.SERVICE, "Tool registration and unregistration", test_tool_registry))

    def test_session_lifecycle():
        rec = svc.create_session("sess_01", "agent-x", "0.9.0")
        assert rec.info.session_id == "sess_01"
        assert rec.status.value == "active"
        svc.terminate_session("sess_01")
        assert svc.get_session("sess_01").status.value == "terminated"

    cases.append(_execute_test("TEST-SVC-02", McpTestCategory.SERVICE, "Session creation and termination", test_session_lifecycle))
    return cases



def _run_config_tests() -> List[McpTestCase]:
    cases: List[McpTestCase] = []

    def test_defaults_validation():
        cfg = McpServerCoreConfig()
        cfg.validate()
        assert cfg.store_path == ".aios/mcp_store.json"
        assert MIN_ACTIVE_SESSIONS <= cfg.max_active_sessions <= MAX_ALLOWED_ACTIVE_SESSIONS

    cases.append(_execute_test("TEST-CFG-01", McpTestCategory.CONFIG, "Default configuration validation", test_defaults_validation))

    def test_traversal_rejection():
        cfg = McpServerCoreConfig(store_path="../traversal/evil.json")
        try:
            cfg.validate()
            raise AssertionError("traversal was not rejected")
        except McpConfigError as e:
            assert "MCPCFG-INV1" in str(e)

    cases.append(_execute_test("TEST-CFG-02", McpTestCategory.CONFIG, "Store path traversal rejection", test_traversal_rejection))
    return cases


def _run_security_tests() -> List[McpTestCase]:
    cases: List[McpTestCase] = []
    handler = McpApiHandler()

    def test_por_invariant_i2():
        call_msg = json.dumps({
            "jsonrpc": "2.0",
            "id": 101,
            "method": "tools/call",
            "params": {"name": "aios.admin.reload", "arguments": {}},
        })
        res = handler.handle_raw_message(call_msg)
        assert res.get("error") is not None
        assert res["error"]["code"] == ERR_UNAUTHORIZED

    cases.append(_execute_test("TEST-SEC-01", McpTestCategory.SECURITY, "PoR Invariant I-2: aios.admin.* requires grant", test_por_invariant_i2))

    def test_nul_byte_rejection():
        call_msg = json.dumps({
            "jsonrpc": "2.0",
            "id": 102,
            "method": "tools/call",
            "params": {"name": "aios.fs.read", "arguments": {"path": "/tmp/a\0b"}},
        })
        res = handler.handle_raw_message(call_msg)
        assert res.get("error") is not None

    cases.append(_execute_test("TEST-SEC-02", McpTestCategory.SECURITY, "NUL byte injection refusal", test_nul_byte_rejection))
    return cases


def run_category_tests(category: str) -> McpTestSuiteReport:
    """Run tests for a single category per SPEC-MCP-SERVER-CORE-TESTS."""
    if not category or len(category) > 64:
        raise ValueError(f"Unknown category: '{category}'")
    cat_str = category.lower().strip()
    t0 = time.perf_counter()
    cases: List[McpTestCase] = []
    if cat_str in ("data_model", "data"):
        cases = _run_data_model_tests()
    elif cat_str in ("api", "wire"):
        cases = _run_api_tests()
    elif cat_str in ("service", "svc"):
        cases = _run_service_tests()
    elif cat_str in ("config", "cfg"):
        cases = _run_config_tests()
    elif cat_str in ("security", "sec"):
        cases = _run_security_tests()
    else:
        raise ValueError(f"Unknown category: {category}")

    t1 = time.perf_counter()
    passed = sum(1 for c in cases if c.passed)
    failed = len(cases) - passed
    return McpTestSuiteReport(
        suite_name=f"mcp_{cat_str}_tests",
        total_cases=len(cases),
        passed_cases=passed,
        failed_cases=failed,
        duration_seconds=t1 - t0,
        cases=cases,
    )


def run_all_mcp_tests() -> McpTestSuiteReport:
    """Run all MCP server core automated test suites per SPEC-MCP-SERVER-CORE-TESTS."""
    t0 = time.perf_counter()
    all_cases: List[McpTestCase] = []
    all_cases.extend(_run_data_model_tests())
    all_cases.extend(_run_api_tests())
    all_cases.extend(_run_service_tests())
    all_cases.extend(_run_config_tests())
    all_cases.extend(_run_security_tests())
    t1 = time.perf_counter()

    passed = sum(1 for c in all_cases if c.passed)
    failed = len(all_cases) - passed
    return McpTestSuiteReport(
        suite_name="mcp_server_core_automated_tests",
        total_cases=len(all_cases),
        passed_cases=passed,
        failed_cases=failed,
        duration_seconds=t1 - t0,
        cases=all_cases,
    )


def register_mcp_tests_tools(mcp_app: Any) -> None:
    """Register MCP Server Core automated tests diagnostic tools with FastMCP (T-03118)."""
    @mcp_app.tool()
    def aios_mcp_test_run(category: Optional[str] = None) -> dict:
        """Run MCP Server Core automated test suite and return structured report."""
        try:
            if category:
                report = run_category_tests(category)
            else:
                report = run_all_mcp_tests()
            return {"ok": True, "report": report.to_dict()}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

