#!/usr/bin/env python3
"""CI Smoke Orchestration — suite registry & result schemas (T-00113).

Data-model contract: docs/tasks/evidence/T-00112-spec.md.
The registry MIRRORS ci/run_all_smokes.sh 1:1 (names, order, commands);
ORDER IS CONTRACT because suites share code/aiosh-cli/dist rebuilds and
the sequential rule is documented in the bash header.

Single-writer/executor note (T-00111 D4): bash remains the executor for
now; this module is the single source any future runner must consume.

Scaffold stage (T-00113): registry data is COMPLETE and validated at
import; the record-constructor / writer FUNCTION BODIES fail loudly until
T-00114 implementation.
"""

from __future__ import annotations

import json
import os
from typing import Any, Literal, TypedDict
from ci_config import CiConfig

#: Default wall-clock bound per suite (G5: bash has none today).
_cfg = CiConfig.from_env()
DEFAULT_TIMEOUT_S = _cfg.timeout_default_s
#: rust_smoke compiles four crates and runs cross-substrate parity legs.
RUST_SMOKE_TIMEOUT_S = _cfg.timeout_default_s * 2

#: Log naming convention owned by ci/run_all_smokes.sh.
LOG_TEMPLATE = "/tmp/aiosh-ci-{name}.log"

Status = Literal["pass", "fail", "timeout", "error"]


class SuiteDef(TypedDict):
    name: str
    command: list[str]
    timeout_s: int


class ResultRecord(TypedDict):
    suite: str
    index: int
    status: Status
    exit_code: int | None
    duration_ms: int
    started_at: str
    finished_at: str
    log_path: str


class RunSummary(TypedDict):
    tool: str
    schema_version: int
    started_at: str
    finished_at: str
    total: int
    passed: int
    failed: int
    all_pass: bool
    results: list[ResultRecord]


def _bash(*args: str) -> list[str]:
    return ["bash", *args]


def _py(script: str) -> list[str]:
    return ["python3", script]


SUITES: list[SuiteDef] = [
    {"name": "rust_smoke",
     "command": _bash("code/aiosh-rust/ci/rust_smoke.sh"),
     "timeout_s": RUST_SMOKE_TIMEOUT_S},
    {"name": "classifier_smoke",
     "command": _py("code/aiosh-mcp/tests/test_classifier_smoke.py"),
     "timeout_s": DEFAULT_TIMEOUT_S},
    {"name": "mcp_smoke",
     "command": _py("code/aiosh-mcp/tests/test_smoke.py"),
     "timeout_s": DEFAULT_TIMEOUT_S},
    {"name": "task_service_smoke",
     "command": _py("code/aiosh-mcp/tests/test_task_service_smoke.py"),
     "timeout_s": DEFAULT_TIMEOUT_S},
    {"name": "task_mcp_smoke",
     "command": _py("code/aiosh-mcp/tests/test_task_mcp_smoke.py"),
     "timeout_s": DEFAULT_TIMEOUT_S},
    {"name": "pentest_smoke",
     "command": _py("code/aiosh-mcp/tests/test_pentest_smoke.py"),
     "timeout_s": DEFAULT_TIMEOUT_S},
    {"name": "sandbox_smoke",
     "command": _py("code/aiosh-mcp/tests/test_sandbox_smoke.py"),
     "timeout_s": DEFAULT_TIMEOUT_S},
    {"name": "retention_smoke",
     "command": _py("code/aiosh-mcp/tests/test_retention_smoke.py"),
     "timeout_s": DEFAULT_TIMEOUT_S},
    {"name": "demo_smoke",
     "command": _py("code/aiosh-mcp/tests/test_demo_smoke.py"),
     "timeout_s": DEFAULT_TIMEOUT_S},
    {"name": "metrics_smoke",
     "command": _py("code/aiosh-mcp/tests/test_metrics_smoke.py"),
     "timeout_s": DEFAULT_TIMEOUT_S},
    {"name": "cli_bash_smoke",
     "command": _bash("code/aiosh-cli/tests/smoke.sh"),
     "timeout_s": DEFAULT_TIMEOUT_S},
    {"name": "task_cli_smoke",
     "command": _py("code/aiosh-cli/tests/test_task_cli_smoke.py"),
     "timeout_s": DEFAULT_TIMEOUT_S},
    {"name": "task_config_smoke",
     "command": _py("code/aiosh-cli/tests/test_task_config_smoke.py"),
     "timeout_s": DEFAULT_TIMEOUT_S},
    {"name": "task_matrix_smoke",
     "command": _py("code/aiosh-mcp/tests/test_ledger_matrix_smoke.py"),
     "timeout_s": DEFAULT_TIMEOUT_S},
    {"name": "security_policy",
     "command": _py("tools/check_security_policy.py"),
     "timeout_s": DEFAULT_TIMEOUT_S},
    {"name": "task_ledger_unit",
     "command": _py("tools/test_task_ledger.py"),
     "timeout_s": DEFAULT_TIMEOUT_S},
    {"name": "task_ledger_scaffold",
     "command": _py("tools/test_task_ledger_scaffold.py"),
     "timeout_s": DEFAULT_TIMEOUT_S},
    {"name": "task_docs_unit",
     "command": _py("tools/test_task_docs.py"),
     "timeout_s": DEFAULT_TIMEOUT_S},
    {"name": "task_docs_scaffold",
     "command": _py("tools/test_task_docs_scaffold.py"),
     "timeout_s": DEFAULT_TIMEOUT_S},
    # T-00126: core-service suite joins the registry (tail append keeps
    # every pre-existing index stable).
    {"name": "ci_service_unit",
     "command": _py("tools/test_ci_service.py"),
     "timeout_s": DEFAULT_TIMEOUT_S},
    # T-00366: Toolchain Pinning automated smoke test suites
    {"name": "toolchain_cli_smoke",
     "command": _py("code/aiosh-cli/tests/test_toolchain_cli_smoke.py"),
     "timeout_s": DEFAULT_TIMEOUT_S},
    {"name": "toolchain_mcp_smoke",
     "command": _py("code/aiosh-mcp/tests/test_toolchain_mcp_smoke.py"),
     "timeout_s": DEFAULT_TIMEOUT_S},
    # T-00466: Documentation Index Control automated test suites
    {"name": "doc_cli_smoke",
     "command": _py("code/aiosh-cli/tests/test_doc_cli_smoke.py"),
     "timeout_s": DEFAULT_TIMEOUT_S},
    {"name": "doc_mcp_smoke",
     "command": _py("code/aiosh-mcp/tests/test_doc_mcp_smoke.py"),
     "timeout_s": DEFAULT_TIMEOUT_S},
    {"name": "doc_index_suites",
     "command": _py("tools/test_doc_index_suites.py"),
     "timeout_s": DEFAULT_TIMEOUT_S},
    # T-00566: Evidence & Audit Trail automated test suites
    {"name": "evidence_cli_smoke",
     "command": _py("code/aiosh-cli/tests/test_evidence_cli_smoke.py"),
     "timeout_s": DEFAULT_TIMEOUT_S},
    {"name": "evidence_mcp_smoke",
     "command": _py("code/aiosh-mcp/tests/test_evidence_mcp_smoke.py"),
     "timeout_s": DEFAULT_TIMEOUT_S},
    {"name": "evidence_checker",
     "command": _py("tools/check_evidence.py"),
     "timeout_s": DEFAULT_TIMEOUT_S},
    {"name": "evidence_unit",
     "command": _py("tools/test_check_evidence.py"),
     "timeout_s": DEFAULT_TIMEOUT_S},
    # T-02887: Continuous Restraint Conformance Gate (Invariant I-5) —
    # tail append keeps every pre-existing index stable.
    {"name": "por_conformance",
     "command": _py("tools/test_por_conformance_suites.py"),
     "timeout_s": DEFAULT_TIMEOUT_S},
]

# Import-time validation (spec §5): fail at load, never mid-run.
_seen: set[str] = set()
for _s in SUITES:
    if not isinstance(_s.get("name"), str) or not _s["name"]:
        raise ValueError("suite with missing/empty name in SUITES")
    if _s["name"] in _seen:
        raise ValueError(f"duplicate suite name in SUITES: {_s['name']!r}")
    _seen.add(_s["name"])
    cmd = _s.get("command")
    if not isinstance(cmd, list) or not cmd or \
            not all(isinstance(c, str) for c in cmd):
        raise ValueError(f"suite {_s['name']!r}: command must be a non-empty "
                         f"list of strings")
    if not isinstance(_s.get("timeout_s"), int) or _s["timeout_s"] <= 0:
        raise ValueError(f"suite {_s['name']!r}: timeout_s must be positive int")

SUITE_NAMES: tuple[str, ...] = tuple(s["name"] for s in SUITES)

#: Summary artifact path (env-overridable, spec §4/D3).
RESULTS_PATH = _cfg.results_path


_VALID_STATUSES = ("pass", "fail", "timeout", "error")


def build_result_record(*, suite: str, index: int, status: str,
                        exit_code: int | None, duration_ms: int,
                        started_at: str, finished_at: str) -> ResultRecord:
    """Validated pure constructor for one suite's result record.

    Contract: docs/tasks/evidence/T-00112-spec.md §3. Raises ValueError
    naming the field on any violation; `timeout`/`error` statuses force
    exit_code to null (spec §3 mapping).
    """
    if suite not in _seen:
        raise ValueError(f"unknown suite {suite!r} (not in SUITES)")
    if not isinstance(index, int) or not (0 <= index < len(SUITES)):
        raise ValueError(f"'index' must be 0..{len(SUITES) - 1}, got {index!r}")
    if SUITE_NAMES[index] != suite:
        raise ValueError(
            f"'index' {index} belongs to suite "
            f"{SUITE_NAMES[index]!r}, not {suite!r} (order is contract)")
    if status not in _VALID_STATUSES:
        raise ValueError(
            f"'status' must be one of {_VALID_STATUSES}, got {status!r}")
    if status in ("timeout", "error"):
        exit_code = None
    elif not isinstance(exit_code, int):
        raise ValueError("'exit_code' must be an int for pass/fail records")
    if not isinstance(duration_ms, int) or duration_ms < 0:
        raise ValueError(f"'duration_ms' must be a non-negative int, "
                         f"got {duration_ms!r}")
    for field, val in (("started_at", started_at), ("finished_at", finished_at)):
        if not isinstance(val, str) or not val.endswith("Z"):
            raise ValueError(f"{field!r} must be an ISO-8601 Z timestamp")
    return {
        "suite": suite,
        "index": index,
        "status": status,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "started_at": started_at,
        "finished_at": finished_at,
        "log_path": LOG_TEMPLATE.format(name=suite),
    }


def write_summary(summary: RunSummary, path: str | None = None) -> str:
    """Atomic summary artifact writer (tmp + fsync + os.replace).

    Mirrors tools/task_ledger.py::save_state_atomic durability rules;
    removes its own temp file on any write error (no orphan temps).
    Returns the written path.
    """
    target = path or RESULTS_PATH
    data = summary_to_json(summary) + "\n"
    tmp = f"{target}.tmp.{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        try:
            os.write(fd, data.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, target)
    except OSError:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    return target


def summary_to_json(summary: RunSummary) -> str:
    """Canonical-ish serialization (sorted keys, compact separators)."""
    return json.dumps(summary, sort_keys=True, separators=(",", ":"))
