#!/usr/bin/env python3
"""AIOS CI orchestrator — executes tools/ci_suites.SUITES sequentially.

Integration of the data model (T-00116). Contract:
docs/tasks/evidence/T-00112-spec.md + the sequential-execution contract
inherited from ci/run_all_smokes.sh:

  SEQUENTIAL IS A CONTRACT: suites share code/aiosh-cli/dist rebuilds;
  never run two suites at once.

Behavior parity with the legacy bash runner (kept intentionally):
  * same per-suite human lines: `==> [name] starting`, `PASS: name`,
    `FAIL: name — last 40 lines of <log>` ;
  * same log paths /tmp/aiosh-ci-<name>.log ;
  * same fail-fast semantics (exit 1 on first non-pass);
  * final line `== ALL <n> SMOKE SUITES PASS ==`.

Additions (this epic): per-suite wall-clock timeouts (G5), and an
atomic machine-readable run summary written to
$AIOSH_CI_RESULTS (default /tmp/aiosh-ci-results.json).

Known limitations (honest): on timeout, subprocess.run kills the direct
child only — grandchild processes may linger (bash runner had no timeout
at all); the summary records status="timeout".
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from ci_suites import (  # noqa: E402
    SUITES,
    build_result_record,
    write_summary,
)

REPO = HERE.parent
TOOL_VERSION = 1


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _host_repair() -> None:
    """Ported verbatim from the legacy bash header: npm/tsc shims can
    lose exec bits in sandboxes; restore cheaply before anything runs."""
    bin_dir = REPO / "code" / "aiosh-cli" / "node_modules" / ".bin"
    if bin_dir.is_dir():
        for entry in bin_dir.iterdir():
            try:
                entry.chmod(entry.stat().st_mode | 0o111)
            except OSError:
                pass  # best-effort repair; suite failures will surface


def _effective_command(argv: list[str]) -> list[str]:
    """Honor the legacy $PYTHON override (bash used PY=${PYTHON:-python3}).

    Also resolve bare `bash` through $AIOSH_BASH / PATH lookup: on Windows,
    CreateProcess finds System32\\bash.exe (WSL) before any PATH entry, which
    silently reroutes every bash suite to a host without installed distros.
    A PATH-only lookup (shutil.which) finds the intended Git Bash first.
    """
    py = os.environ.get("PYTHON")
    if py and argv and argv[0] == "python3":
        return [py, *argv[1:]]
    if argv and argv[0] == "bash":
        override = os.environ.get("AIOSH_BASH")
        if override:
            return [override, *argv[1:]]  # explicit operator trust
        bash = shutil.which("bash")
        if bash:
            _validate_interpreter(bash, "bash")
            return [bash, *argv[1:]]
        raise RuntimeError(
            "bash not resolvable via PATH; set $AIOSH_BASH to a known-good shell")
    return argv


def _validate_interpreter(path: str, name: str) -> None:
    """TV-CRC-01 (T-02889): refuse to execute an interpreter from a
    world-writable directory (POSIX mode check; skipped on Windows where
    mode bits are unreliable). Raises on violation — fail-closed, never
    silently rerouted."""
    resolved = Path(path).resolve()
    if not resolved.is_file():
        raise RuntimeError(f"interpreter {name!r} not found at {resolved}")
    if os.name == "posix" and (resolved.parent.stat().st_mode & 0o002):
        raise RuntimeError(
            f"refusing to run {name!r} from world-writable {resolved.parent}")


from ci_config import CiConfig
_cfg = CiConfig.from_env()

def _print_failure_tail(log_path: str, max_bytes: int = _cfg.max_file_bytes,
                        max_lines: int = 40) -> None:
    """Bounded tail read (T-00118): never loads more than `max_bytes`
    from the log into memory — a hostile/pathological suite must not be
    able to DoS the orchestrator via log volume."""
    try:
        size = os.path.getsize(log_path)
        with open(log_path, "rb") as f:
            if size > max_bytes:
                f.seek(size - max_bytes)
            data = f.read()
        text = data.decode("utf-8", errors="replace")
        # Drop the partial first line created by the seek boundary.
        if size > max_bytes and "\n" in text:
            text = text.split("\n", 1)[1]
        sys.stdout.write("".join(text.splitlines(keepends=True)[-max_lines:])
                         or "(empty log)\n")
    except OSError as e:
        print(f"(could not read log {log_path}: {e})")


def _terminate_group(proc: subprocess.Popen) -> None:
    """Kill the whole process GROUP (T-00118, closes review finding S4
    residual): suites may spawn children that would otherwise survive a
    direct-child kill. Falls back to proc.kill() when the child never
    got its own session."""
    try:
        os.killpg(os.getpgid(proc.pid), 15)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            pass


def main() -> int:
    _host_repair()
    print("== AIOS CI: all smoke suites (sequential, fail-fast) ==")
    print(f"root={REPO}")
    print()

    results = []
    started_at = _now()
    t0 = time.monotonic()

    for index, suite in enumerate(SUITES):
        name = suite["name"]
        log_path = suite_log = f"/tmp/aiosh-ci-{name}.log"
        print(f"==> [{name}] starting")
        suite_started = time.monotonic()
        ts_start = _now()
        # Own process group so a timeout can kill the whole tree
        # (T-00118 hardening; see _terminate_group).
        proc = subprocess.Popen(
            _effective_command(suite["command"]),
            cwd=str(REPO),
            stdout=open(log_path, "w"),
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            rc = proc.wait(timeout=suite["timeout_s"])
            duration_ms = int((time.monotonic() - suite_started) * 1000)
            if rc == 0:
                status = "pass"
                print(f"PASS: {name} ({duration_ms} ms)")
            else:
                status = "fail"
                print(f"FAIL: {name} (exit {rc}) — "
                      f"last 40 lines of {log_path}:")
                _print_failure_tail(log_path)
            record = build_result_record(
                suite=name, index=index, status=status,
                exit_code=rc, duration_ms=duration_ms,
                started_at=ts_start, finished_at=_now())
            results.append(record)
            if status != "pass":
                break  # sequential fail-fast contract
        except subprocess.TimeoutExpired:
            _terminate_group(proc)
            proc.wait()
            duration_ms = int((time.monotonic() - suite_started) * 1000)
            print(f"FAIL: {name} (timeout after {suite['timeout_s']}s) — "
                  f"last 40 lines of {log_path}:")
            _print_failure_tail(log_path)
            results.append(build_result_record(
                suite=name, index=index, status="timeout",
                exit_code=None, duration_ms=duration_ms,
                started_at=ts_start, finished_at=_now()))
            break
        except OSError as e:
            print(f"FAIL: {name} (spawn error: {e})")
            results.append(build_result_record(
                suite=name, index=index, status="error",
                exit_code=None,
                duration_ms=int((time.monotonic() - suite_started) * 1000),
                started_at=ts_start, finished_at=_now()))
            break

    passed = sum(1 for r in results if r["status"] == "pass")
    failed = len(results) - passed
    summary = {
        "tool": "aios-ci-orchestrator",
        "schema_version": TOOL_VERSION,
        "started_at": started_at,
        "finished_at": _now(),
        "total": len(results),
        "passed": passed,
        "failed": failed,
        "all_pass": failed == 0 and len(results) == len(SUITES),
        "results": results,
    }
    # Summary persistence must NEVER mask the run verdict.
    try:
        write_summary(summary, path=os.environ.get("AIOSH_CI_RESULTS"))
    except OSError as e:
        print(f"(warning: could not write CI summary artifact: {e})", file=sys.stderr)

    wall_ms = int((time.monotonic() - t0) * 1000)
    if failed:
        print(f"\n== {failed} SUITE(S) FAILED after {len(results)} run "
              f"({wall_ms} ms); summary: "
              f"{os.environ.get('AIOSH_CI_RESULTS') or '/tmp/aiosh-ci-results.json'} ==")
        return 1
    print(f"\n== ALL {passed} SMOKE SUITES PASS ({wall_ms} ms) ==")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
