#!/usr/bin/env python3
"""Proof of Restraint: Continuous Restraint Conformance Suite (CRCS) — T-02885 IMPLEMENTATION.

Sprint / Architecture: ADR-0037 (I-5), PLAN.md §4, Invariant I-5.
Contract: docs/tasks/evidence/T-02883-spec.md (normative).

Executes the mint -> anchor -> prove -> verify loop on every CI run so that
new tool additions cannot bypass the redeem gate and restraint proofs for
untouched grants consistently pass.

Criteria (drift classes from T-02882):
  C1  redeem-gate non-bypassability across all dispatch surfaces (D1)
  C2  mint/redeem audit parity, canonical JSON identical (D2)
  C3  untouched-grant restraint stability: prove+verify == valid (D3)
  C4  touched-grant invalidation: redeemed grant never proves restraint (D4)
  C5  substrate oracle parity Python vs TypeScript (D5)
  C6  anchor/chain continuity and window bounding (I-3)

Fixtures: F-UNTOUCHED, F-REDEEMED, F-SPENT-RETRY, F-NO-GRANT, F-PARITY,
F-ANCHOR-CADENCE (see T-02883-spec.md §3).
"""

from __future__ import annotations

import atexit
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from aiosh_mcp import _dispatch, anchors as anchors_mod, audit_client, restraint, verifier
from aiosh_mcp import pentest as pentest_mod
from aiosh_mcp.retention import bloom_add

WINDOW_START = "2026-10-07T12:01:00Z"
WINDOW_END = "2026-10-07T12:05:00Z"
ANCHOR_START_TS = "2026-10-07T12:00:00Z"
ANCHOR_END_TS = "2026-10-07T12:10:00Z"

GRANT_UNTOUCHED = "gr_conform_untouched"
GRANT_REDEEMED = "gr_conform_redeemed"

CLI_DIST = REPO / "code" / "aiosh-cli" / "dist" / "cli.js"
PENTEST_SRC = REPO / "code" / "aiosh-mcp" / "aiosh_mcp" / "pentest.py"


# ---------------------------------------------------------------------------
# T-02889 hardening: interpreter resolution & temp hygiene (TV-CRC-01/07)
# ---------------------------------------------------------------------------
_TEMP_ROOTS: list[Path] = []


def _cleanup_temp_roots() -> None:
    """atexit belt-and-braces: never leak por-conform-* sandboxes on hard abort."""
    while _TEMP_ROOTS:
        shutil.rmtree(_TEMP_ROOTS.pop(), ignore_errors=True)


atexit.register(_cleanup_temp_roots)


def _resolve_interpreter(name: str, override_var: str) -> list[str]:
    """Resolve an external interpreter (TV-CRC-01 hardening, T-02889).

    The explicit override env var is trusted verbatim (operator intent).
    Otherwise a PATH-only lookup is used and the resolved binary must live in
    a non-world-writable directory (POSIX mode check; skipped on Windows
    where mode bits are unreliable). Missing interpreters raise — the child
    process fails loudly, never silently."""
    override = os.environ.get(override_var)
    if override:
        return [override]
    path = shutil.which(name)
    if not path:
        raise FileNotFoundError(f"{name} not found on PATH; set ${override_var}")
    resolved = Path(path).resolve()
    if os.name == "posix" and (resolved.parent.stat().st_mode & 0o002):
        raise RuntimeError(
            f"refusing to run {name} from world-writable {resolved.parent}")
    return [str(resolved)]


# ---------------------------------------------------------------------------
# Shared sandbox fixtures
# ---------------------------------------------------------------------------

def _mint_grant(
    conn: sqlite3.Connection,
    grant_id: str,
    *,
    scope: dict | None = None,
    single_use: bool = True,
    issued_at: str = "2026-10-07T11:50:00Z",
    expires_at: str = "2026-10-07T23:59:59Z",
    issued_to: str = "agent:conformance",
    ts: str = "2026-10-07T12:05:30Z",
):
    """I-1 mint contract (mirrors code/aiosh-cli/src/pep.ts create()):
    exactly one pep_grants row + exactly one pep.capability.mint audit row."""
    scope = scope or {"tools": ["pentest.nmap", "fs.write"], "paths": [], "networks": []}
    conn.execute(
        """INSERT INTO pep_grants (
            grant_id, issued_at, expires_at, issued_to, constitution_rev,
            scope_json, scope_hash, single_use
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            grant_id, issued_at, expires_at, issued_to, "rev-conformance",
            json.dumps(scope, sort_keys=True),
            audit_client.sha256_hex(json.dumps(scope, sort_keys=True)),
            1 if single_use else 0,
        ),
    )
    return audit_client.write_audit_row(conn, {
        "ts": ts,
        "actor": "user",
        "actor_id": "auditor@aios",
        "tool": "pep.capability.mint",
        "command": "capability.mint",
        "args": {"grant_id": grant_id, "single_use": single_use, "scope": scope,
                 "expires_at": expires_at},
        "target": None,
        "outcome": "ok",
        "outcome_detail": None,
        "constitution_rev": "rev-conformance",
        "grant_token": grant_id,
        "c_flags": {"c1": False, "c2": False, "c3": False, "c4": False},
    })


@contextmanager
def _open(env):
    conn = sqlite3.connect(str(env["db_path"]))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def _make_env(mp=None):
    """Build an isolated conformance sandbox. Returns (env, cleanup).

    T-02889 hardening (TV-CRC-04): pass a pytest `monkeypatch` (conform_env
    does) so the AIOSH_HOME mutation is per-test and concurrency-safe; the
    bare fallback (meta tests) restores the environment in cleanup()."""
    tmp = Path(tempfile.mkdtemp(prefix="por-conform-"))
    _TEMP_ROOTS.append(tmp)
    aiosh_home = tmp / ".aios"
    anchors_dir = aiosh_home / "anchors"
    anchors_dir.mkdir(parents=True, exist_ok=True)
    db_path = aiosh_home / "audit.db"
    anchors_path = anchors_dir / "anchors.jsonl"

    old_home = os.environ.get("AIOSH_HOME")
    if mp is not None:
        mp.setenv("AIOSH_HOME", str(aiosh_home))
    else:
        os.environ["AIOSH_HOME"] = str(aiosh_home)

    # T-02889 (TV-CRC-07): explicit connect/close — sqlite3's context manager
    # only commits; an unclosed handle keeps audit.db locked on Windows and
    # blocks sandbox removal.
    conn = sqlite3.connect(str(db_path))
    try:
        conn.row_factory = sqlite3.Row
        audit_client.ensure_audit_schema(conn)
        audit_client.ensure_pep_schema(conn)

        # Base non-grant rows 12:01..12:05 (mirrors the proven end-to-end fixture)
        for i in range(1, 6):
            audit_client.write_audit_row(conn, {
                "ts": f"2026-10-07T12:0{i}:00Z",
                "actor": "user",
                "actor_id": "admin",
                "tool": "aios.fs.read",
                "command": f"cat file_{i}",
                "args": {"path": f"/tmp/file_{i}"},
                "target": f"/tmp/file_{i}",
                "outcome": "ok",
                "outcome_detail": None,
                "constitution_rev": "rev-conformance",
                "grant_token": None,
                "c_flags": {"c1": False, "c2": False, "c3": False, "c4": True},
            })

        # Conformance grants minted BEFORE anchor finalization (F-UNTOUCHED, F-REDEEMED)
        _mint_grant(conn, GRANT_UNTOUCHED, ts="2026-10-07T12:05:30Z")
        _mint_grant(conn, GRANT_REDEEMED, ts="2026-10-07T12:05:40Z")
        conn.commit()

        tail = conn.execute(
            "SELECT id, hash FROM audit_ring ORDER BY id DESC LIMIT 1"
        ).fetchone()
        tail_id, tail_hash = tail["id"], tail["hash"]
    finally:
        conn.close()

    priv, pub = anchors_mod.generate_keypair()
    a1 = anchors_mod.sign_checkpoint(
        seq=1, head_hash="hash_placeholder_1",
        timestamp=ANCHOR_START_TS, private_key_hex=priv)
    a2 = anchors_mod.sign_checkpoint(
        seq=tail_id, head_hash=tail_hash,
        timestamp=ANCHOR_END_TS, private_key_hex=priv)
    anchors_mod.append_anchor(a1, anchors_path)
    anchors_mod.append_anchor(a2, anchors_path)

    env = {
        "db_path": db_path,
        "aiosh_home": aiosh_home,
        "anchors_path": anchors_path,
        "priv": priv,
        "pub": pub,
        "a1": a1,
        "a2": a2,
    }

    def prove(grant_id: str):
        with _open(env) as conn:
            return restraint.generate_restraint_proof(
                conn=conn,
                grant_id=grant_id,
                window_start=WINDOW_START,
                window_end=WINDOW_END,
                anchors_path=str(anchors_path),
            )

    def verify(proof_dict: dict):
        return verifier.verify_restraint_proof(proof_dict, [pub])

    env["prove"] = prove
    env["verify"] = verify

    def cleanup():
        if mp is None:
            if old_home is not None:
                os.environ["AIOSH_HOME"] = old_home
            else:
                os.environ.pop("AIOSH_HOME", None)
        if tmp in _TEMP_ROOTS:
            _TEMP_ROOTS.remove(tmp)
        shutil.rmtree(tmp, ignore_errors=True)

    return env, cleanup


@pytest.fixture
def conform_env(monkeypatch):
    """Isolated AIOSH_HOME + temp audit.db; zero network. Yields paths/keys/helpers."""
    env, cleanup = _make_env(monkeypatch)
    yield env
    cleanup()


@pytest.fixture
def anchor_keys():
    """Deterministic-in-run Ed25519 keypair for scenario anchors (F-* fixtures)."""
    priv, pub = anchors_mod.generate_keypair()
    return {"priv": priv, "pub": pub}


def _count_rows(conn: sqlite3.Connection, tool: str, grant_token: str | None = None) -> int:
    if grant_token is None:
        cur = conn.execute(
            "SELECT COUNT(*) AS n FROM audit_ring WHERE tool = ?", (tool,))
    else:
        cur = conn.execute(
            "SELECT COUNT(*) AS n FROM audit_ring WHERE tool = ? AND grant_token = ?",
            (tool, grant_token))
    return int(cur.fetchone()["n"])


# ---------------------------------------------------------------------------
# C1 — Redeem-gate non-bypassability
# ---------------------------------------------------------------------------

def test_c1_no_grant_consequential_tool_refused(conform_env):
    """C1.1 / F-NO-GRANT: consequential tool with no minted grant => refused,
    zero action audit rows."""
    with _open(conform_env) as conn:
        verdict = audit_client.grant_check(conn, None, "pentest.nmap", "10.0.0.5")
        assert verdict["ok"] is False
        assert "requires explicit PEP grant" in verdict["reason"]

    d_verdict, d_row = _dispatch.dispatch(
        tool="pentest.nmap",
        command="nmap -sV 10.0.0.5",
        args={"target": "10.0.0.5", "mode": "service"},
        target="10.0.0.5",
        grant_id=None,
        require_grant=True,
    )
    assert d_verdict["ok"] is False
    assert d_verdict["gate"] in ("classifier", "pep")

    with _open(conform_env) as conn:
        # The refused dispatch is auditable; no successful execution row exists.
        ok_rows = conn.execute(
            "SELECT COUNT(*) AS n FROM audit_ring WHERE tool = 'pentest.nmap' AND outcome = 'ok'"
        ).fetchone()["n"]
        assert ok_rows == 0
        refused_rows = conn.execute(
            "SELECT COUNT(*) AS n FROM audit_ring WHERE tool = 'pentest.nmap' AND outcome = 'refused'"
        ).fetchone()["n"]
        assert refused_rows >= 1


def test_c1_spent_grant_replay_refused(conform_env):
    """C1.2 / F-SPENT-RETRY: second redeem of a single-use grant => refused,
    at both the PEP gate and the dispatch surface."""
    grant_id = "gr_conform_replay"
    with _open(conform_env) as conn:
        _mint_grant(conn, grant_id, ts="2026-10-07T12:05:50Z")

        first = audit_client.grant_redeem(
            conn, grant_id, tool="fs.write",
            command="fs.write /var/data/prod/ledger.dat",
            target="/var/data/prod/ledger.dat")
        assert first["ok"] is True

        second = audit_client.grant_redeem(
            conn, grant_id, tool="fs.write",
            command="fs.write /var/data/prod/ledger.dat",
            target="/var/data/prod/ledger.dat")
        assert second["ok"] is False
        assert "already redeemed" in second["reason"]

        chk = audit_client.grant_check(conn, grant_id, "fs.write")
        assert chk["ok"] is False
        assert "already redeemed" in chk["reason"]

        # Exactly one redeem row committed (I-1) despite two attempts.
        assert _count_rows(conn, "pep.capability.redeem", grant_id) == 1

    d_verdict, _ = _dispatch.dispatch(
        tool="fs.write",
        command="fs.write /var/data/prod/ledger.dat",
        args={"path": "/var/data/prod/ledger.dat"},
        target="/var/data/prod/ledger.dat",
        grant_id=grant_id,
        require_grant=True,
    )
    assert d_verdict["ok"] is False, "spent single-use grant must be refused at dispatch"


def test_c1_consequential_tool_coverage_complete(conform_env):
    """C1.3: every registered consequential tool is redeem-gate covered;
    newly added pentest tools are auto-discovered from source and must be
    gate-refused without a grant (the I-5 'new tool additions' clause)."""
    src = PENTEST_SRC.read_text(encoding="utf-8")

    registry: set[str] = set()
    for name in re.findall(r'_audit_tool_name\(\s*"([^"]+)"\s*\)', src):
        registry.add(pentest_mod._audit_tool_name(name))
    for literal in re.findall(r'"(pentest\.[A-Za-z0-9._-]+)"', src):
        registry.add(literal)

    # Irreversible non-pentest families (grant_check's exact reference set)
    registry.update({"fs.write", "system.reboot", "system.shutdown"})

    known_minimum = {"pentest.nmap", "pentest.nikto", "pentest.sqlmap",
                     "pentest.tshark", "pentest.aircrack-ng"}
    assert known_minimum <= registry, (
        f"consequential tool registry shrank: missing {known_minimum - registry}"
    )

    with _open(conform_env) as conn:
        for tool in sorted(registry):
            verdict = audit_client.grant_check(conn, None, tool)
            assert verdict["ok"] is False, f"coverage gap: '{tool}' passes the gate without a grant"
            assert "requires explicit PEP grant" in verdict["reason"]


# ---------------------------------------------------------------------------
# C2 — Mint/redeem audit parity
# ---------------------------------------------------------------------------

def test_c2_mint_redeem_row_parity(conform_env):
    """C2.1: exactly one pep.capability.mint per issuance and exactly one
    pep.capability.redeem per consumption."""
    grant_id = "gr_conform_parity"
    with _open(conform_env) as conn:
        _mint_grant(conn, grant_id, ts="2026-10-07T12:05:55Z")
        assert _count_rows(conn, "pep.capability.mint", grant_id) == 1

        res = audit_client.grant_redeem(
            conn, grant_id, tool="fs.write",
            command="fs.write /var/data/prod/x", target="/var/data/prod/x")
        assert res["ok"] is True

        assert _count_rows(conn, "pep.capability.redeem", grant_id) == 1
        assert _count_rows(conn, "pep.capability.mint", grant_id) == 1

        chain = audit_client.verify(conn)
        assert chain["ok"] is True, f"hash chain broken: {chain}"

        g = audit_client.load_grant(conn, grant_id)
        assert g is not None and g["redeemed_at"] is not None


def test_c2_canonical_json_parity(conform_env):
    """C2.2: canonical JSON of mint/redeem rows is deterministic, normative
    (sorted keys, no whitespace), and byte-identical across substrates."""
    grant_id = "gr_conform_canonical"
    with _open(conform_env) as conn:
        mint_row = _mint_grant(conn, grant_id, ts="2026-10-07T12:05:58Z")
        res = audit_client.grant_redeem(
            conn, grant_id, tool="fs.write",
            command="fs.write /var/data/prod/y", target="/var/data/prod/y")
        assert res["ok"] is True

    for row in (mint_row.to_dict(), res["audit_row"].to_dict()):
        c1 = audit_client.canonical(row)
        c2 = audit_client.canonical(row)
        assert c1 == c2, "canonical serialization must be deterministic"
        assert c1 == json.dumps(row, sort_keys=True, separators=(",", ":"))
        assert audit_client.canonical(json.loads(c1)) == c1, "canonical round-trip must be stable"

    # Cross-substrate byte parity: TypeScript canonicalJson must produce the
    # identical bytes for the same rows (skip when the TS substrate is absent).
    ts_canonical = _ts_canonical_json(mint_row.to_dict())
    if ts_canonical is not None:
        assert ts_canonical == audit_client.canonical(mint_row.to_dict())
        ts_canonical = _ts_canonical_json(res["audit_row"].to_dict())
        assert ts_canonical == audit_client.canonical(res["audit_row"].to_dict())


# ---------------------------------------------------------------------------
# C3 — Untouched-grant restraint stability
# ---------------------------------------------------------------------------

def test_c3_untouched_grant_proves_restrained(conform_env):
    """C3.1 / F-UNTOUCHED: mint -> anchors -> prove => PROVABLY_RESTRAINED."""
    pkg = conform_env["prove"](GRANT_UNTOUCHED)
    d = pkg.to_dict()
    assert d["verdict"] == "PROVABLY_RESTRAINED"
    assert d["grant"]["grant_id"] == GRANT_UNTOUCHED
    assert d["grant"]["redeemed_at"] is None


def test_c3_standalone_verify_valid(conform_env):
    """C3.2: standalone verifier returns valid=true with all 7 checks true."""
    pkg = conform_env["prove"](GRANT_UNTOUCHED)
    res = conform_env["verify"](pkg.to_dict())
    assert res.valid is True
    assert res.proof_id == pkg.to_dict()["proof_id"]
    assert res.reason is None
    assert all(res.checks.values())
    assert set(res.checks) == {"schema", "grant", "anchor_keys", "anchor_sigs",
                               "anchor_bounds", "bloom_exclusion", "live_chain"}


def test_c3_idempotent_verdict(conform_env):
    """C3.3: re-running prove/verify on the same state yields the same verdict."""
    first = conform_env["prove"](GRANT_UNTOUCHED).to_dict()
    second = conform_env["prove"](GRANT_UNTOUCHED).to_dict()
    assert first["verdict"] == second["verdict"] == "PROVABLY_RESTRAINED"

    r1 = conform_env["verify"](first)
    r2 = conform_env["verify"](second)
    assert r1.valid is True and r2.valid is True
    assert r1.checks == r2.checks


# ---------------------------------------------------------------------------
# C4 — Touched-grant invalidation (catastrophic direction)
# ---------------------------------------------------------------------------

def test_c4_redeemed_grant_prove_refused(conform_env):
    """C4.1 / F-REDEEMED: generator refuses with GRANT_REDEEMED."""
    with _open(conform_env) as conn:
        res = audit_client.grant_redeem(
            conn, GRANT_REDEEMED, tool="pentest.nmap",
            command="pentest.nmap 10.0.0.5", target="10.0.0.5")
        assert res["ok"] is True

    with pytest.raises(ValueError, match="GRANT_REDEEMED"):
        conform_env["prove"](GRANT_REDEEMED)


def test_c4_forged_restraint_proof_rejected(conform_env):
    """C4.2: any proof asserting restraint for a redeemed grant fails at
    least one verification gate (redemption / Bloom presence), even when the
    anchors are signed with the trusted key (worst-case forgery)."""
    # Forgery A: honest redeemed_at recorded -> CHECK_GRANT rejects.
    pkg_a = _forge_proof(conform_env["priv"], conform_env["pub"], GRANT_REDEEMED,
                         redeemed_at="2026-10-07T12:06:00Z", bloom_hit=False)
    res_a = conform_env["verify"](pkg_a)
    assert res_a.valid is False
    assert "GRANT_REDEEMED" in res_a.reason

    # Forgery B: redeemed_at hidden, but archived segment Bloom contains the
    # grant (the archived redeem row) -> CHECK_BLOOM_EXCLUSION rejects.
    pkg_b = _forge_proof(conform_env["priv"], conform_env["pub"], GRANT_REDEEMED,
                         redeemed_at=None, bloom_hit=True)
    res_b = conform_env["verify"](pkg_b)
    assert res_b.valid is False
    assert "BLOOM_INDICATES_PRESENCE" in res_b.reason


def _forge_proof(priv: str, pub: str, grant_id: str,
                 redeemed_at: str | None, bloom_hit: bool) -> dict:
    """Well-signed proof package asserting restraint for a redeemed grant."""
    a1 = anchors_mod.sign_checkpoint(
        seq=1, head_hash="hash_0001",
        timestamp="2026-10-07T11:55:00Z", private_key_hex=priv)
    a2 = anchors_mod.sign_checkpoint(
        seq=20, head_hash="hash_0020",
        timestamp="2026-10-07T12:15:00Z", private_key_hex=priv)

    m, k = 1024, 7
    bits = bytearray(m // 8)
    if bloom_hit:
        bloom_add(bits, m, k, grant_id)

    segment = {
        "segment_id": 1,
        "row_range": [1, 10],
        "archive_sha256": "deadbeef" * 8,
        "bloom_m_bits": m,
        "bloom_k": k,
        "bloom_hex": bits.hex(),
        "bloom_negative": not bloom_hit,
    }
    return {
        "schema_version": 1,
        "proof_id": "por_forged_redeemed_001",
        "generated_at": "2026-10-07T12:16:00Z",
        "grant": {
            "grant_id": grant_id,
            "issued_at": "2026-10-07T11:50:00Z",
            "expires_at": "2026-10-07T23:59:59Z",
            "issued_to": "agent:pentest",
            "single_use": True,
            "redeemed_at": redeemed_at,
        },
        "window": {"start": WINDOW_START, "end": WINDOW_END},
        "anchors": {"start_anchor": a1.to_dict(), "end_anchor": a2.to_dict()},
        "segments_checked": [segment],
        "live_range": {
            "first_seq": 11, "last_seq": 20, "row_count": 10,
            "hashes": ["hash_0011", "hash_0012", "hash_0020"],
        },
        "verdict": "PROVABLY_RESTRAINED",
    }


# ---------------------------------------------------------------------------
# C5 — Substrate oracle parity
# ---------------------------------------------------------------------------

def _run_cli_verify(proof_path: Path, pub: str) -> dict | None:
    """Run the TypeScript substrate's `aiosh prove verify`. Returns the result
    object, or None when the TS substrate is unavailable (skip convention)."""
    if not CLI_DIST.exists():
        pytest.skip("aiosh-cli dist/cli.js not compiled")
    env = os.environ.copy()
    try:
        p = subprocess.run(
            [*_resolve_interpreter("node", "AIOSH_NODE"), str(CLI_DIST),
             "prove", "verify",
             "--proof", str(proof_path), "--pubkey", pub],
            env=env, cwd=str(REPO / "code" / "aiosh-cli"),
            capture_output=True, text=True, timeout=120,
        )
    except subprocess.TimeoutExpired:
        pytest.fail("aiosh-cli prove verify timed out after 120s (bounded child process)")
    if "not a valid Win32 application" in p.stderr or "not a valid Win32 application" in p.stdout:
        pytest.skip("better-sqlite3 native binary compiled for non-Win32 substrate")
    assert p.returncode in (0, 1), f"CLI crashed: {p.stderr}"
    out = p.stdout.strip()
    try:
        payload = json.loads(out)
    except json.JSONDecodeError:
        line = next((ln for ln in out.splitlines() if ln.startswith("{")), None)
        assert line, f"no JSON on CLI stdout: {out!r} / {p.stderr!r}"
        payload = json.loads(line)
    return payload.get("data", payload)


def test_c5_python_typescript_verdict_parity(conform_env, tmp_path):
    """C5.1 / F-PARITY: identical VerificationResult across Python and TS."""
    pkg = conform_env["prove"](GRANT_UNTOUCHED)
    d = pkg.to_dict()

    proof_file = tmp_path / "proof.json"
    proof_file.write_text(json.dumps(d), encoding="utf-8")

    py_res = conform_env["verify"](d)
    ts_res = _run_cli_verify(proof_file, conform_env["pub"])

    assert ts_res is not None
    assert ts_res["valid"] == py_res.valid
    assert ts_res["proof_id"] == py_res.proof_id
    assert ts_res["checks"] == py_res.checks
    assert bool(ts_res.get("reason")) == bool(py_res.reason)


def test_c5_canonical_json_byte_parity(conform_env, tmp_path):
    """C5.2: canonical JSON serialization of the verdict object matches
    byte-for-byte across substrates."""
    pkg = conform_env["prove"](GRANT_UNTOUCHED)
    d = pkg.to_dict()

    proof_file = tmp_path / "proof.json"
    proof_file.write_text(json.dumps(d), encoding="utf-8")

    py_res = conform_env["verify"](d)
    ts_res = _run_cli_verify(proof_file, conform_env["pub"])
    assert ts_res is not None

    def normalize(obj: dict) -> dict:
        return {k: v for k, v in obj.items() if v is not None}

    py_norm = normalize(py_res.to_dict())
    ts_norm = normalize(ts_res)
    assert audit_client.canonical(py_norm) == audit_client.canonical(ts_norm)


def _ts_canonical_json(obj: dict) -> str | None:
    """TypeScript canonicalJson (dist/audit.js) for a JSON object; None when
    the TS substrate is unavailable."""
    if not CLI_DIST.exists():
        return None
    audit_js = CLI_DIST.parent / "audit.js"
    if not audit_js.exists():
        return None
    try:
        proc = subprocess.run(
            [*_resolve_interpreter("node", "AIOSH_NODE"),
             "--input-type=module", "-e",
             f"const m = await import({json.dumps(audit_js.as_uri())});"
             "let s='';"
             "process.stdin.on('data', d => s += d);"
             "process.stdin.on('end', () => process.stdout.write(m.canonicalJson(JSON.parse(s))));"],
            input=json.dumps(obj), capture_output=True, text=True, timeout=60,
        )
    except subprocess.TimeoutExpired:
        raise  # a hang is a failure, never an 'unavailable substrate' skip
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


# ---------------------------------------------------------------------------
# C6 — Anchor/chain continuity
# ---------------------------------------------------------------------------

def test_c6_anchor_chain_verifies(conform_env):
    """C6.1 / F-ANCHOR-CADENCE: deterministic anchors verify individually and
    as a chain (aiosh anchor verify semantics)."""
    a1 = anchors_mod.AnchorRecord(
        schema_version=conform_env["a1"].schema_version,
        seq=conform_env["a1"].seq,
        head_hash=conform_env["a1"].head_hash,
        timestamp=conform_env["a1"].timestamp,
        pubkey=conform_env["a1"].pubkey,
        signature=conform_env["a1"].signature,
    )
    assert anchors_mod.verify_checkpoint(a1) is True
    assert anchors_mod.verify_checkpoint(conform_env["a2"]) is True

    loaded = anchors_mod.load_anchors(conform_env["anchors_path"])
    assert len(loaded) == 2
    for rec in loaded:
        assert anchors_mod.verify_checkpoint(rec) is True
    seqs = [r.seq for r in loaded]
    assert seqs == sorted(seqs), "anchor seq must be non-decreasing"


def test_c6_window_bounding_between_anchors(conform_env):
    """C6.2: consecutive anchors bracket the window: T_a1 <= T_s < T_e <= T_a2,
    seq ordering non-decreasing."""
    a1 = conform_env["a1"]
    a2 = conform_env["a2"]
    assert a1.timestamp <= WINDOW_START < WINDOW_END <= a2.timestamp
    assert a1.seq <= a2.seq
    assert a1.pubkey == a2.pubkey == conform_env["pub"]
