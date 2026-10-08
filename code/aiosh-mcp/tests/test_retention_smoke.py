"""Sprint 3 — audit-ring retention smoke (ADR-0036 / SPEC-AUDIT-RETENTION).

Proves the checkpointed segment-rotation retention policy end-to-end,
in both substrates, without breaking the Sprint 0/1/2 invariants:

  R1: Python rotate(keep_rows) → segment checkpoint + JSONL archive +
      bloom; live verify anchors at checkpoint head; chain continues
      across the boundary when new rows are written.
  R2: verify(full=True) replays the archive byte-for-byte; a single
      corrupted byte fails it (sha256 pin); restore → passes again.
  R3: seen() — archived hash → maybe/exact 'archive'; live hash →
      'live'; unknown hash → 'no' (bloom: no false negatives over
      every archived hash).
  R4: rotate on a BROKEN live chain refuses (and records the refusal);
      rotation can never launder a tampered chain.
  R5: dry-run changes nothing (no segment, no file, same row count).
  R6: cross-substrate — TS CLI rotate on the same DB → Python
      verify/verify_full/seen all pass against it (canonical-JSON +
      bloom + anchor contract holds across languages).
  R7: MCP gate — aios.audit.rotate without grant → refused at the PEP
      gate; with a grant scoped audit.rotate → rotates.
"""

from __future__ import annotations

import hashlib
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
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aiosh_mcp import audit_client as ac
from aiosh_mcp import retention as rt
from aiosh_mcp.server import aios_audit_rotate, aios_audit_seen, aios_audit_segments

WORKDIR = Path(__file__).resolve().parent
PROJ = WORKDIR.parent
AIOSH_CLI = PROJ.parent / "aiosh-cli"
CONSTITUTION = PROJ.parent.parent / "mostimportanAIfolder/AI_CONSTITUTION.md"

PASS = "[✓]"
FAIL = "[✗]"


def step_0_precheck() -> bool:
    subprocess.run(["node", "--version"], check=True, capture_output=True)
    # T-02902: `npx` is a .cmd shim on Windows that CreateProcess cannot
    # spawn; run the same tsc via node directly.
    r = subprocess.run(
        ["node", str(AIOSH_CLI / "node_modules" / "typescript" / "bin" / "tsc"),
         "-p", "tsconfig.json"],
        cwd=str(AIOSH_CLI), capture_output=True, text=True, encoding="utf-8")
    if r.returncode != 0:
        print(f"{FAIL} tsc: {r.stderr}")
        return False
    print(f"{PASS} aiosh-cli tsc clean")
    return True


def _write(conn, i: int, tool: str = "test.tool") -> ac.AuditRow:
    return ac.write_audit_row(conn, {
        "ts": ac.utcnow_iso(), "actor": "system", "actor_id": "system:ret-smoke",
        "tool": tool, "command": f"{tool} {i}", "args": {"i": i},
        "target": None, "outcome": "ok", "outcome_detail": None,
        "constitution_rev": None, "grant_token": None,
        "c_flags": {"c1": False, "c2": False, "c3": False, "c4": True},
    })


def step_1_python_rotate(home: Path) -> bool:
    """R1: rotate keep=2 of 6 rows; anchor + chain continuity."""
    conn = ac.open_db(str(home / "audit.db"))
    rows = [_write(conn, i) for i in range(6)]
    res = rt.rotate(conn, keep_rows=2, actor="system", actor_id="system:ret-smoke")
    if not (res.get("ok") and res.get("rotated") and res.get("archived_rows") == 4):
        print(f"{FAIL} R1 rotate: {res}")
        return False
    live = conn.execute(
        "SELECT id, prev_hash, hash FROM audit_ring ORDER BY id ASC").fetchall()
    if len(live) != 3:  # 2 kept + the audit.rotate row
        print(f"{FAIL} R1 live row count {len(live)} != 3")
        return False
    if live[0]["prev_hash"] != res["head_hash"]:
        print(f"{FAIL} R1 first kept row not anchored at segment head")
        return False
    if live[-1]["prev_hash"] != live[-2]["hash"]:
        print(f"{FAIL} R1 rotation row does not chain from kept tail")
        return False
    v = ac.verify(conn)
    if not v["ok"] or v["anchor"] != res["head_hash"]:
        print(f"{FAIL} R1 verify: {v}")
        return False
    _write(conn, 99)  # chain must continue after rotation
    v2 = ac.verify(conn)
    if not v2["ok"] or v2["checked"] != 4:
        print(f"{FAIL} R1 post-rotation write verify: {v2}")
        return False
    conn.close()
    print(f"{PASS} R1 python rotate keep=2: segment={res['segment_id']} "
          f"archived=4 live=3(+1) anchor ok, chain continues")
    return True


def step_2_verify_full_and_tamper(home: Path) -> bool:
    """R2: full replay + sha256 tamper detection."""
    conn = ac.open_db(str(home / "audit.db"))
    vf = rt.verify_full(conn)
    if not (vf["ok"] and vf["archive_checked"] == 4 and vf["segments"] == 1):
        print(f"{FAIL} R2 verify_full: {vf}")
        return False
    seg = rt.list_segments(conn)[0]
    p = Path(seg["archive_path"])
    data = p.read_bytes()
    p.write_bytes(data[:-10] + b"X" + data[-9:])
    bad = rt.verify_full(conn)
    if bad["ok"] or "sha256" not in (bad.get("error") or ""):
        print(f"{FAIL} R2 tampered archive not detected: {bad}")
        return False
    p.write_bytes(data)  # restore
    if not rt.verify_full(conn)["ok"]:
        print(f"{FAIL} R2 restored archive does not verify")
        return False
    conn.close()
    print(f"{PASS} R2 verify_full archive=4 live ok; 1-byte tamper detected "
          f"via sha256 pin; restore verifies")
    return True


def step_3_seen_bloom(home: Path) -> bool:
    """R3: seen() semantics + no bloom false negatives."""
    conn = ac.open_db(str(home / "audit.db"))
    seg = rt.list_segments(conn)[0]
    archived_hashes = [
        json.loads(ln)["hash"]
        for ln in Path(seg["archive_path"]).read_text().split("\n") if ln]
    for h in archived_hashes:
        s = rt.seen(conn, h)
        if s["found"] != "maybe" or seg["segment_id"] not in s["segments"]:
            print(f"{FAIL} R3 bloom false NEGATIVE for archived hash: {s}")
            return False
    s_exact = rt.seen(conn, archived_hashes[0], exact=True)
    live_row = ac.tail(conn, 1)[-1]
    s_live = rt.seen(conn, live_row.hash)
    s_none = rt.seen(conn, "ab" * 32)
    if s_exact["found"] != "archive":
        print(f"{FAIL} R3 exact: {s_exact}")
        return False
    if s_live["found"] != "live":
        print(f"{FAIL} R3 live: {s_live}")
        return False
    if s_none["found"] != "no":
        print(f"{FAIL} R3 unknown: {s_none}")
        return False
    conn.close()
    print(f"{PASS} R3 seen: {len(archived_hashes)} archived hashes all "
          f"bloom-hit (no false negatives), exact→archive, live→live, "
          f"unknown→no")
    return True


def step_4_broken_chain_refused(home: Path) -> bool:
    """R4: rotation refuses a tampered live chain (and audits refusal)."""
    home2 = Path(tempfile.mkdtemp(prefix="aiosh-ret-broken-", dir=str(home.parent)))
    conn = ac.open_db(str(home2 / "audit.db"))
    _write(conn, 1)
    _write(conn, 2)
    conn.execute("UPDATE audit_ring SET hash='deadbeef' WHERE id=1")
    conn.commit()
    before = conn.execute("SELECT COUNT(*) AS n FROM audit_ring").fetchone()["n"]
    res = rt.rotate(conn, keep_rows=0)
    after = conn.execute("SELECT COUNT(*) AS n FROM audit_ring").fetchone()["n"]
    if res.get("ok") or "broken" not in (res.get("error") or ""):
        print(f"{FAIL} R4 rotate on broken chain not refused: {res}")
        return False
    refused = conn.execute(
        "SELECT * FROM audit_ring WHERE tool='audit.rotate' "
        "AND outcome='refused' ORDER BY id DESC LIMIT 1").fetchone()
    if refused is None:
        print(f"{FAIL} R4 refusal not audited")
        return False
    if after != before + 1:
        print(f"{FAIL} R4 unexpected row delta {before}->{after}")
        return False
    conn.close()
    print(f"{PASS} R4 broken-chain rotate refused + refusal audited "
          f"(rows {before}→{after})")
    return True


def step_5_dry_run(home: Path) -> bool:
    """R5: dry-run previews without touching anything."""
    conn = ac.open_db(str(home / "audit.db"))
    before = conn.execute("SELECT COUNT(*) AS n FROM audit_ring").fetchone()["n"]
    segs_before = len(rt.list_segments(conn))
    res = rt.rotate(conn, keep_rows=0, dry_run=True)
    after = conn.execute("SELECT COUNT(*) AS n FROM audit_ring").fetchone()["n"]
    segs_after = len(rt.list_segments(conn))
    if not (res.get("ok") and res.get("dry_run") and not res.get("rotated")):
        print(f"{FAIL} R5 dry-run result: {res}")
        return False
    if res.get("would_archive", 0) < 1:
        print(f"{FAIL} R5 dry-run would_archive: {res}")
        return False
    if after != before or segs_after != segs_before:
        print(f"{FAIL} R5 dry-run mutated state ({before}→{after}, "
              f"{segs_before}→{segs_after})")
        return False
    conn.close()
    print(f"{PASS} R5 dry-run: would_archive={res['would_archive']}, "
          f"no state change")
    return True


def _cli(home: Path, *args: str, expect_ok: bool = True) -> dict:
    env = {**os.environ, "AIOSH_HOME": str(home),
           "AIOSH_CONSTITUTION": str(CONSTITUTION)}
    out = subprocess.run(
        ["node", "dist/cli.js", *args],
        cwd=str(AIOSH_CLI), env=env, capture_output=True, text=True)
    parsed = json.loads(out.stdout or out.stderr)
    if parsed.get("ok") is not expect_ok:
        raise AssertionError(f"CLI {' '.join(args)}: {parsed}")
    return parsed


def step_6_ts_rotates_py_verifies(home: Path) -> bool:
    """R6: cross-substrate — TS CLI rotate; Python verifies everything."""
    # Seed a few more live rows via the TS CLI itself.
    for _ in range(3):
        _cli(home, "status")
    rot = _cli(home, "audit", "rotate", "--keep", "1")
    data = rot["data"]
    if not (data.get("rotated") and data.get("segment_id") == 2):
        print(f"{FAIL} R6 TS rotate: {data}")
        return False
    conn = ac.open_db(str(home / "audit.db"))
    v = ac.verify(conn)
    if not (v["ok"] and v["anchor"] == data["head_hash"]):
        print(f"{FAIL} R6 python live verify on TS-rotated DB: {v}")
        return False
    vf = rt.verify_full(conn)
    if not (vf["ok"] and vf["segments"] == 2):
        print(f"{FAIL} R6 python verify_full on TS-rotated DB: {vf}")
        return False
    # Python bloom must hit hashes archived by TS (cross-language bloom).
    seg2 = [s for s in rt.list_segments(conn) if s["segment_id"] == 2][0]
    h = json.loads(Path(seg2["archive_path"]).read_text().split("\n")[0])["hash"]
    bits = bytes.fromhex(seg2["bloom_hex"])
    if not rt.bloom_test(bits, seg2["bloom_m_bits"], seg2["bloom_k"], h):
        print(f"{FAIL} R6 python bloom misses TS-archived hash")
        return False
    s = rt.seen(conn, h, exact=True)
    if s["found"] != "archive" or 2 not in s["segments"]:
        print(f"{FAIL} R6 python seen on TS archive: {s}")
        return False
    conn.close()
    # TS verify --full must agree too.
    full = _cli(home, "audit", "verify", "--full")
    if not (full["data"].get("archive_checked", 0) >= 1
            and full["data"].get("segments") == 2):
        print(f"{FAIL} R6 TS verify --full: {full['data']}")
        return False
    print(f"{PASS} R6 cross-substrate: TS rotate segment 2 → python "
          f"verify/verify_full/bloom/seen all pass; TS verify --full "
          f"archive_checked={full['data']['archive_checked']}")
    return True


def step_7_mcp_gate(home: Path) -> bool:
    """R7: MCP aios.audit.rotate requires a PEP grant."""
    env = {**os.environ, "AIOSH_HOME": str(home),
           "AIOSH_CONSTITUTION": str(CONSTITUTION)}
    r1 = aios_audit_rotate(keep_rows=0)
    if r1.get("ok") is not False or r1.get("gate") != "pep":
        print(f"{FAIL} R7 no-grant rotate not refused by PEP: {r1}")
        return False
    grant_out = _cli(home, "grant", "create",
                     "--to", "agent:ret-smoke@ci",
                     "--tools", "audit.rotate", "--ttl", "600")
    gid = grant_out["data"]["grant_id"]
    r2 = aios_audit_rotate(keep_rows=0, grant_id=gid)
    if not (r2.get("ok") and r2.get("rotated")):
        print(f"{FAIL} R7 granted rotate failed: {r2}")
        return False
    r3 = aios_audit_segments()
    if not (r3.get("ok") and r3.get("count") == 3):
        print(f"{FAIL} R7 segments listing: {r3}")
        return False
    # seen via MCP on an archived hash
    conn = ac.open_db(str(home / "audit.db"))
    seg = rt.list_segments(conn)[-1]
    h = json.loads(Path(seg["archive_path"]).read_text().split("\n")[0])["hash"]
    conn.close()
    r4 = aios_audit_seen(h, exact=True)
    if r4.get("found") != "archive":
        print(f"{FAIL} R7 MCP seen: {r4}")
        return False
    print(f"{PASS} R7 MCP gate: no-grant refused (gate=pep), granted rotate "
          f"segment={r2['segment_id']}, segments count=3, seen→archive")
    return True


def main() -> int:
    print("== Sprint 3 audit-ring retention smoke ==")
    if not step_0_precheck():
        return 1
    home = Path(tempfile.mkdtemp(prefix="aiosh-ret-smoke-"))
    os.environ["AIOSH_HOME"] = str(home)
    os.environ["AIOSH_CONSTITUTION"] = str(CONSTITUTION)
    print(f"AIOSH_HOME={home}")

    steps = [
        step_1_python_rotate,
        step_2_verify_full_and_tamper,
        step_3_seen_bloom,
        step_4_broken_chain_refused,
        step_5_dry_run,
        step_6_ts_rotates_py_verifies,
        step_7_mcp_gate,
    ]
    for step in steps:
        try:
            if not step(home):
                return 1
        except Exception as e:
            print(f"{FAIL} {step.__name__} exception: {e}")
            return 1
    print()
    print("PASS: Sprint 3 retention smoke (rotation + bloom + cross-substrate "
          "+ tamper detection + MCP grant gate)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
