"""AI Control Plane Model Backend Adapters Automated Tests Harness (T-03215 scaffold / T-03216 impl).

Provides synthetic test execution matrix and reporting for model backend adapters.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import time
from typing import Any, Dict, List, Optional

from aiosh_mcp.model_backend_adapters_data_model import (
    ModelEndpointConfig,
    ModelMessage,
    ModelProviderType,
    ModelRequest,
    ModelResponse,
)
from aiosh_mcp.model_backend_adapters_service import (
    ModelBackendService,
    ModelServiceError,
    redact_secrets,
)


@dataclass
class ModelTestCase:
    name: str
    request: ModelRequest
    expected_status: str = "success"
    expect_error_code: Optional[int] = None
    fault_inject: Optional[str] = None


@dataclass
class ModelTestReport:
    total: int = 0
    passed: int = 0
    failed: int = 0
    duration_ms: int = 0
    results: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "duration_ms": self.duration_ms,
            "pass_rate": round(self.passed / self.total, 2) if self.total > 0 else 0.0,
            "results": self.results,
        }


class ModelTestRunner:
    def __init__(self, service: ModelBackendService):
        self.service = service

    async def run_case(self, case: ModelTestCase) -> Dict[str, Any]:
        t0 = time.time()
        status = "failed"
        error_msg = None

        try:
            resp = await self.service.complete(case.request)
            if case.expected_status == "success":
                status = "passed"
            else:
                error_msg = f"Expected failure '{case.expected_status}' but succeeded"
        except ModelServiceError as e:
            if case.expected_status == "error":
                status = "passed"
            else:
                error_msg = redact_secrets(str(e))
        except Exception as e:
            if case.expected_status == "error":
                status = "passed"
            else:
                error_msg = redact_secrets(str(e))

        elapsed_ms = int((time.time() - t0) * 1000)
        return {
            "name": case.name,
            "model_id": case.request.model_id,
            "status": status,
            "duration_ms": elapsed_ms,
            "error": error_msg,
        }

    async def run_suite(self, cases: List[ModelTestCase]) -> ModelTestReport:
        t0 = time.time()
        report = ModelTestReport(total=len(cases))

        for case in cases:
            res = await self.run_case(case)
            report.results.append(res)
            if res["status"] == "passed":
                report.passed += 1
            else:
                report.failed += 1

        report.duration_ms = int((time.time() - t0) * 1000)
        return report
