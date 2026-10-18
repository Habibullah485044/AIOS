"""AI Control Plane MCP Server Core Automated Tests Subsystem (T-03115 scaffold / T-03116 impl).

Defines test case data models, test suite report envelopes, and runner interfaces
in compliance with SPEC-MCP-SERVER-CORE-TESTS and PoR Invariant I-2.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


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


def run_category_tests(category: str) -> McpTestSuiteReport:
    """Run tests for a single category per SPEC-MCP-SERVER-CORE-TESTS."""
    raise NotImplementedError("run_category_tests scaffold — implementation in T-03116")


def run_all_mcp_tests() -> McpTestSuiteReport:
    """Run all MCP server core automated test suites per SPEC-MCP-SERVER-CORE-TESTS."""
    raise NotImplementedError("run_all_mcp_tests scaffold — implementation in T-03116")
