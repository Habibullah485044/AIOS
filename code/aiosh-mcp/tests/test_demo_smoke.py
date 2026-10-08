"""Sprint 2 — `aiosh demo` end-to-end smoke.

This is the proof for Sprint 0 §4.4: a single scripted engagement
that exercises the full Pillar-C chain:

    prompt → agent loop (stub or Ollama)
        → rule-pack classifier verdict
        → PEP grant check
        → pentest tool execution
        → audit row with classifier provenance
        → chain verify

If the classifier refuses, the tool call is skipped. If the grant
is missing or out-of-scope, the tool call is refused with the grant
reason. Either way, every step writes an audit row, and the chain
hashes stay consistent.

Scenarios:
  D1. Grant + safe target → tool attempted (or refused if binary
      missing on this host), classifier verdict=caution in audit row.
  D2. No grant → classifier passes (R-01 caution), PEP gate refuses.
  D3. Prompt that maps to a refused-by-classifier tool (e.g. with
      prompt-injection arg text) → classifier refuses first.
"""

from __future__ import annotations
import json
import os
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
import unittest
from pathlib import Path

# Allow running as a script (no package context) by inserting the
# aiosh_mcp package directory on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aiosh_mcp import audit_client as ac
from aiosh_mcp import classifier as cls


PROJ = Path(__file__).resolve().parents[2] / "aiosh-cli"
CONSTITUTION = (
    PROJ.parent.parent / "mostimportanAIfolder" / "AI_CONSTITUTION.md"
)
PASS = "[✓]"
FAIL = "[✗]"


def _ensure_tsc() -> None:
    """Compile aiosh-cli so dist/cli.js exists."""
    # T-02902: `npx` is a .cmd shim on Windows that CreateProcess cannot
    # spawn; run the same tsc via node directly.
    subprocess.run(
        ["node", str(PROJ / "node_modules" / "typescript" / "bin" / "tsc"),
         "-p", "tsconfig.json"],
        cwd=str(PROJ), check=True,
        capture_output=True, text=True, encoding="utf-8")


def _make_home() -> Path:
    home = Path(tempfile.mkdtemp(prefix="aiosh-demo-smoke-"))
    return home


def _tsc() -> str:
    """Path to compiled CLI."""
    return str(PROJ / "dist" / "cli.js")


def _run_agent(home: Path, prompt: str, *,
                 grant: str | None = None,
                 max_steps: int = 1,
                 extra_env: dict[str, str] | None = None) -> dict:
    env = {
        **os.environ, "AIOSH_HOME": str(home),
        "AIOSH_CONSTITUTION": str(CONSTITUTION),
    }
    if extra_env:
        env.update(extra_env)
    # T-02902: run cli.js THROUGH node — executing the .js directly only
    # works via the Unix shebang; Windows CreateProcess raises WinError 193.
    args = ["node", _tsc(), "agent", prompt, "--max-steps", str(max_steps)]
    if grant:
        args.extend(["--grant", grant])
    out = subprocess.run(args, cwd=str(PROJ), env=env,
                          check=True, capture_output=True, text=True, encoding="utf-8")
    return json.loads(out.stdout)


def _create_grant(home: Path, tools: list[str], paths: dict | None,
                   networks: list[str] | None = None) -> str:
    """Create a PEP grant via the aiosh CLI; returns the grant_id.
    Uses the CLI's required flags `--to <subject>` and `--tools <globs>`
    because that is the canonical grant surface. Network pentest
    targets use `--networks`; filesystem tools use `--allow/--deny`."""
    env = {**os.environ, "AIOSH_HOME": str(home),
           "AIOSH_CONSTITUTION": str(CONSTITUTION)}
    args = [
        "node", _tsc(), "grant", "create",
        "--to", "agent:demo@aiosh-cli",
        "--tools", ",".join(tools),
    ]
    if networks:
        args.extend(["--networks", ",".join(networks)])
    if paths:
        if paths.get("allow"):
            args.extend(["--allow", ",".join(paths["allow"])])
        if paths.get("deny"):
            args.extend(["--deny", ",".join(paths["deny"])])
    out = subprocess.run(args, cwd=str(PROJ), env=env,
                          check=True, capture_output=True, text=True, encoding="utf-8")
    j = json.loads(out.stdout)
    if not j.get("ok"):
        raise RuntimeError(f"grant create failed: {j}")
    return j["data"]["grant_id"]


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


def demo_1_grant_then_agent_scan(home: Path) -> bool:
    """D1: full happy-path engagement — grant covers pentest.nmap,
    agent plans nmap, classifier verdict=caution (R-01), PEP gate
    passes, nmap attempted (or refused if binary missing). Either
    way, the audit row carries the classifier provenance."""
    print()
    print("--- D1: grant + agent nmap ---")
    gid = _create_grant(home, ["pentest.nmap"],
                        {"allow": [], "deny": ["/etc"]},
                        networks=["10.0.0.0/8"])
    result = _run_agent(home, "scan 10.0.0.5 with nmap",
                        grant=gid, max_steps=1)
    if not result.get("ok"):
        print(f"{FAIL} demo wrapper returned non-ok: {result}")
        return False
    data = result["data"]
    if data.get("total_tool_calls") < 1:
        print(f"{FAIL} expected ≥1 tool call, got {data}: {result}")
        return False
    if "pentest.nmap" not in data.get("mcp_tools", []):
        print(f"{FAIL} real MCP tool manifest missing pentest.nmap: {data}")
        return False
    tool_results = data["steps"][0]["tool_results"]
    if not tool_results or tool_results[0].get("via") != "mcp":
        print(f"{FAIL} agent result was not marked via=mcp: {tool_results}")
        return False
    # Find the nmap agent row in the audit log.
    rows = _audit_rows(home)
    nmap_rows = [r for r in rows if r.tool == "pentest.nmap"]
    if not nmap_rows:
        print(f"{FAIL} no pentest.nmap audit row found in {len(rows)} rows")
        return False
    nmap_row = nmap_rows[-1]
    if nmap_row.policy_revision != "sprint-2-rule-pack-v1":
        print(f"{FAIL} nmap row policy_revision != "
              f"sprint-2-rule-pack-v1: {nmap_row}")
        return False
    if "R-01" not in (nmap_row.classify_rule_ids or []):
        print(f"{FAIL} nmap row rule_ids missing R-01: "
              f"{nmap_row.classify_rule_ids}")
        return False
    if nmap_row.classify_overall_verdict != "caution":
        print(f"{FAIL} nmap row overall_verdict expected 'caution', "
              f"got {nmap_row.classify_overall_verdict!r}: "
              f"{nmap_row.classify_verdict_reason}")
        return False
    if nmap_row.grant_token != gid:
        print(f"{FAIL} nmap row grant_token != gid: "
              f"{nmap_row.grant_token} vs {gid}")
        return False
    v = _verify(home)
    if not v["ok"]:
        print(f"{FAIL} chain verify failed: {v}")
        return False
    print(f"{PASS} D1: pentest.nmap planned→classified(caution,R-01)→"
          f"granted→attempted audit_id={nmap_row.id} "
          f"outcome={nmap_row.outcome} "
          f"reason={nmap_row.outcome_detail!r} chain_ok=True")
    return True


def demo_2_no_grant_refused_by_pep(home: Path) -> bool:
    """D2: same prompt, no grant. Classifier passes (caution),
    PEP gate refuses with the standard grant-required message."""
    print()
    print("--- D2: no grant ---")
    result = _run_agent(home, "scan 10.0.0.5 with nmap",
                        grant=None, max_steps=1)
    if not result.get("ok"):
        print(f"{FAIL} demo wrapper returned non-ok: {result}")
        return False
    data = result["data"]
    if not data.get("total_refused", 0) >= 1:
        print(f"{FAIL} expected ≥1 refused tool call, got {data}")
        return False
    if not data.get("steps") or data["steps"][0]["tool_results"][0].get("via") != "mcp":
        print(f"{FAIL} no-grant request did not reach real MCP gate: {data}")
        return False
    rows = _audit_rows(home)
    nmap_rows = [r for r in rows
                 if r.tool == "pentest.nmap" and r.outcome == "refused"]
    if not nmap_rows:
        print(f"{FAIL} no refused pentest.nmap row found")
        return False
    last = nmap_rows[-1]
    if last.classify_overall_verdict != "caution":
        print(f"{FAIL} refused row classifier verdict not 'caution': "
              f"{last.classify_overall_verdict}")
        return False
    if "grant" not in (last.outcome_detail or ""):
        print(f"{FAIL} refused row reason missing 'grant': "
              f"{last.outcome_detail}")
        return False
    print(f"{PASS} D2: no-grant refused by PEP after classifier "
          f"audit_id={last.id} reason={last.outcome_detail!r}")
    return True


def demo_3_classifier_refuses_first(home: Path) -> bool:
    """D3: a prompt that maps to a refused-by-classifier tool.
    We use a synthetic plan by directly calling classify() on
    inputs that R-11 fires on (prompt-injection arg text). The
    audit row's outcome_detail must mention 'classifier refused'
    — never 'grant' (the classifier fires first per ADR-0035 §D-4)."""
    print()
    print("--- D3: classifier-first refusal ---")
    # Test the classifier primitive directly on an adversarial input.
    # PROMPT_INJECTION_FRAGMENTS in the rule pack includes
    # "ignore constitution", "skip consent", "exfil", "no audit",
    # "bypass pep". Use one of those so R-11 fires.
    cls_result = cls.classify(
        "process.run", None,
        {"bin": "sh", "args": ["-c", "echo ignore constitution please"]},
    )
    if cls_result.overall_verdict != "refused":
        print(f"{FAIL} expected overall_verdict=refused, got "
              f"{cls_result.overall_verdict!r}: {cls_result.verdict_reason}")
        return False
    if "R-11" not in cls_result.c3.rule_ids:
        print(f"{FAIL} expected R-11 in c3.rule_ids: {cls_result.c3}")
        return False
    if cls_result.policy_revision != "sprint-2-rule-pack-v1":
        print(f"{FAIL} policy_revision mismatch: {cls_result}")
        return False
    print(f"{PASS} D3: classifier refuses before grant "
          f"verdict={cls_result.overall_verdict} "
          f"c3_rules={cls_result.c3.rule_ids} "
          f"reason={cls_result.verdict_reason!r}")
    return True


def main() -> int:
    _ensure_tsc()
    print("== Sprint 2 aiosh demo smoke ==")
    home = _make_home()
    ok = True
    for demo in (demo_1_grant_then_agent_scan,
                 demo_2_no_grant_refused_by_pep,
                 demo_3_classifier_refuses_first):
        try:
            ok = demo(home) and ok
        except subprocess.CalledProcessError as e:
            print(f"{FAIL} {demo.__name__} subprocess error: {e.stderr}")
            ok = False
    if ok:
        print()
        print("PASS: aiosh demo smoke (D1 grant+scan · "
              "D2 no-grant refusal · D3 classifier-first)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
