"""Sprint 2 — Landlock + seccomp-bpf sandbox smoke for `aiosh run`.

The Sprint 0/1/2 carry-over gap: `aiosh run` was logged but not
sandboxed. Sprint 2 wraps every `process.run` call through
`aiosh_mcp.sandbox` which applies prctl(PR_SET_NO_NEW_PRIVS) +
seccomp(SECCOMP_SET_MODE_FILTER) + landlock_create_ruleset before
execve.

Scenarios:

  S1. `aiosh run /bin/ls /tmp` — happy path. Subprocess returns 0;
      audit row carries the sandbox components actually applied.
      We assert the audit row carries at least `no_new_privs=ok` and
      that the audit chain still verifies.

  S2. `aiosh run /bin/ls /` — read of / via default policy (which
      does NOT include / as read-allowed). On a host with Landlock,
      the read should fail with EACCES. On a host without Landlock,
      we assert the subprocess exits 0 (because the sandbox is
      fail-open by design — see docs/SPRINT-0.md §11 honest-position
      paragraph), but the audit row still records that Landlock was
      unavailable. We check both outcomes.

  S3. Chain-verify invariant: after S1+S2 traffic, `verify()` returns
      ok=True, checked=N, broken_at=None. This proves the audit-ring
      canonical-JSON invariant still holds when sandbox events land.

The smoke is **environment-tolerant**: on hosts where the kernel
refuses to install new seccomp filters (common in containerised CI)
or doesn't have Landlock compiled in, the test passes as long as:
  - no_new_privs was applied (always works on Linux)
  - the audit row carries the actual components
  - chain verify passes

This is the **honest position**: when the kernel sandbox is
unavailable, the audit ring still records the policy intent so the
gap is visible, never silent.
"""

from __future__ import annotations
import json
import os
import platform
import subprocess
import sys

# T-02902: pin stdout/stderr to UTF-8 — this suite prints non-ASCII
# markers that the Windows ANSI codepage (cp1252) cannot encode.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
import tempfile
from pathlib import Path

# Allow running as a script (no package context).
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aiosh_mcp import audit_client as ac


PROJ = Path(__file__).resolve().parents[2] / "aiosh-cli"
CONSTITUTION = (
    PROJ.parent.parent / "mostimportanAIfolder" / "AI_CONSTITUTION.md"
)
PASS = "[✓]"
FAIL = "[✗]"
INFO = "[i]"


def _ensure_tsc() -> None:
    # T-02902: `npx` is a .cmd shim on Windows that CreateProcess cannot
    # spawn; run the same tsc via node directly.
    subprocess.run(
        ["node", str(PROJ / "node_modules" / "typescript" / "bin" / "tsc"),
         "-p", "tsconfig.json"],
        cwd=str(PROJ), check=True,
        capture_output=True, text=True, encoding="utf-8")


def _make_home() -> Path:
    return Path(tempfile.mkdtemp(prefix="aiosh-sandbox-smoke-"))


IS_LINUX = platform.system() == "Linux"
# T-02902: the sandbox subject commands must exist on the host. The
# asserted contract (sandbox event recorded, components honestly report
# application-or-refusal, chain intact) is identical on every platform;
# only the subject binary differs.
S1_CMD = (["/bin/ls", "/tmp"] if IS_LINUX
           else ["cmd", "/c", "echo", "sandbox-smoke-ok"])
S2_CMD = (["/bin/cat", "/etc/shadow"] if IS_LINUX
           else ["cmd", "/c", "type",
                 os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                              "System32", "drivers", "etc", "hosts")])
S2_TOKEN = "cat" if IS_LINUX else "type"


def _run_aiosh(home: Path, *args: str,
                extra_env: dict[str, str] | None = None) -> dict:
    env = {
        **os.environ, "AIOSH_HOME": str(home),
        "AIOSH_CONSTITUTION": str(CONSTITUTION),
    }
    if extra_env:
        env.update(extra_env)
    cmd = ["node", str(PROJ / "dist" / "cli.js"), *args]
    out = subprocess.run(cmd, cwd=str(PROJ), env=env,
                          capture_output=True, text=True)
    if out.returncode not in (0, 1):
        # 0=ok, 1=aiosh-reported-failure; both are valid JSON outputs
        raise RuntimeError(
            f"aiosh unexpected exit {out.returncode}: "
            f"stdout={out.stdout[:500]} stderr={out.stderr[:500]}")
    return json.loads(out.stdout)


def _audit_rows(home: Path) -> list:
    conn = ac.open_db(str(home / "audit.db"))
    try:
        cur = conn.execute("SELECT * FROM audit_ring ORDER BY id ASC")
        return [ac.AuditRow.from_sql(r) for r in cur.fetchall()]
    finally:
        conn.close()


def _verify(home: Path) -> dict:
    conn = ac.open_db(str(home / "audit.db"))
    try:
        return ac.verify(conn)
    finally:
        conn.close()


def sandbox_1_happy_path(home: Path) -> bool:
    """S1: aiosh run /bin/ls /tmp — completes, audit row carries
    sandbox components, no_new_privs applied."""
    print()
    print(f"--- S1: aiosh run {' '.join(S1_CMD)} ---")
    res = _run_aiosh(home, "run", *S1_CMD)
    if not res.get("ok"):
        print(f"{FAIL} run returned non-ok: {res}")
        return False
    sandbox = res["data"].get("sandbox")
    if not sandbox:
        print(f"{FAIL} run output missing 'sandbox' component: {res}")
        return False
    components = dict(sandbox.get("components") or [])
    if "no_new_privs" not in components:
        print(f"{FAIL} sandbox.components missing no_new_privs: "
              f"{components}")
        return False
    nnp = components["no_new_privs"]
    nnp_good = (nnp.startswith("ok") if IS_LINUX else nnp.startswith("FAIL:"))
    if not nnp_good:
        print(f"{FAIL} no_new_privs neither ok nor honestly-FAIL: {nnp}")
        return False
    # Audit row carries the sandbox event.
    rows = _audit_rows(home)
    run_rows = [r for r in rows if r.tool == "process.run"]
    if not run_rows:
        print(f"{FAIL} no process.run audit row found in {len(rows)} rows")
        return False
    last = run_rows[-1]
    if last.args.get("sandbox") is None:
        print(f"{FAIL} audit row args.sandbox missing: {last}")
        return False
    v = _verify(home)
    if not v["ok"]:
        print(f"{FAIL} chain verify failed: {v}")
        return False
    print(f"{PASS} S1: aiosh run {' '.join(S1_CMD)} completed; "
          f"audit_id={last.id} chain_ok=True "
          f"components={list(components.keys())}")
    return True


def sandbox_2_default_policy_keeps_etc(home: Path) -> bool:
    """S2: the default Landlock policy does NOT include /etc. With
    Landlock enforced, reading /etc/shadow would fail with EACCES.
    Without Landlock, the subprocess completes — we assert the
    audit row honestly records Landlock's status either way."""
    print()
    print(f"--- S2: aiosh run {' '.join(S2_CMD)} ---")
    res = _run_aiosh(home, "run", *S2_CMD)
    sandbox = (res.get("data") or {}).get("sandbox")
    components = dict((sandbox or {}).get("components") or [])
    landlock_status = components.get("landlock", "")
    seccomp_status = components.get("seccomp", "")
    # Read the audit row.
    rows = _audit_rows(home)
    run_rows = [r for r in rows if r.tool == "process.run"
                and r.outcome == "ok"
                and S2_TOKEN in json.dumps(r.args)]
    last_audit = run_rows[-1] if run_rows else None
    if "landlock ok" in landlock_status:
        # Landlock enforced the policy. cat /etc/shadow must have
        # been blocked.
        if res.get("ok"):
            print(f"{FAIL} Landlock is enforced but cat /etc/shadow "
                  f"succeeded? {res}")
            return False
        print(f"{PASS} S2: Landlock enforced — cat /etc/shadow "
              f"blocked (refused: {res.get('error')!r})")
        return True
    # Landlock not available on this host — the read proceeded, but
    # the audit row MUST honestly record that landlock was not applied.
    if "FAIL" not in landlock_status and "not supported" not in landlock_status:
        print(f"{FAIL} landlock status unrecognised: {landlock_status!r}")
        return False
    if last_audit is None:
        print(f"{FAIL} no process.run audit row for cat /etc/shadow: "
              f"{len(rows)} rows total")
        return False
    if (last_audit.args.get("sandbox") or {}).get("components") is None:
        print(f"{FAIL} audit row args.sandbox.components missing: "
              f"{last_audit}")
        return False
    print(f"{INFO} S2: Landlock not enforced on this host "
          f"(landlock={landlock_status!r}, seccomp={seccomp_status!r})")
    print(f"{PASS} S2: audit row honestly records sandbox "
          f"non-application (audit_id={last_audit.id} outcome=ok, "
          f"but landlock=FAIL visible in args.sandbox.components)")
    return True


def sandbox_3_chain_invariant(home: Path) -> bool:
    """S3: after S1+S2 traffic, chain verify still passes. Proves
    the audit-ring canonical-JSON invariant holds when sandbox
    events (with non-trivial args.sandbox.components JSON) land."""
    print()
    print("--- S3: chain verify ---")
    v = _verify(home)
    if not v["ok"]:
        print(f"{FAIL} chain verify failed: {v}")
        return False
    rows = _audit_rows(home)
    if v["checked"] != len(rows):
        print(f"{FAIL} verify checked={v['checked']} but db has "
              f"{len(rows)} rows")
        return False
    print(f"{PASS} S3: chain verify ok=True checked={v['checked']} "
          f"matches db row count")
    return True


def main() -> int:
    _ensure_tsc()
    print("== Sprint 2 aiosh run sandbox smoke ==")
    home = _make_home()
    ok = True
    for scenario in (sandbox_1_happy_path,
                      sandbox_2_default_policy_keeps_etc,
                      sandbox_3_chain_invariant):
        try:
            ok = scenario(home) and ok
        except subprocess.CalledProcessError as e:
            print(f"{FAIL} {scenario.__name__} subprocess error: "
                  f"{e.stderr[:500]}")
            ok = False
        except Exception as e:
            print(f"{FAIL} {scenario.__name__} exception: {e}")
            ok = False
    if ok:
        print()
        print("PASS: aiosh run sandbox smoke "
              "(S1 happy · S2 default-policy / S2a landlock-enforced · "
              "S3 chain verify)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
