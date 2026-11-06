"""AIOS MCP server — Model Context Protocol tool surface.

ADR-0035 §D-2 binding: MCP is the only tool-call protocol AIOS exposes
to external models.

Spec version pinned at 2025-06-18 (upstream MCP stdio transport for
Sprint 0; we will pin to 2026-07-28 once the corresponding fastmcp
release ships).

Tools (Sprint 1 — Pillar A pentest set added on top of Sprint 0):
    aios.fs.read                 — read a UTF-8 text file (path PEP gated)
    aios.process.list            — list running processes (read-only)
    aios.audit.tail              — tail the audit ring
    aios.audit.verify            — verify the audit-ring hash chain
                                   (full=True replays archived segments, Sprint 3)
    aios.audit.rotate            — seal live rows into an archived segment [grant]
    aios.audit.segments          — list archived rotation checkpoints
    aios.audit.seen              — bloom-backed "was this hash ever logged?"
    ---- (Sprint 1, Pillar A) ----
    aios.pentest.nmap            — TCP recon (top-100 ports)         [C-1]
    aios.pentest.nikto           — web-misconfig scan (safe tuning)  [C-1]
    aios.pentest.sqlmap          — SQL injection (level=1 risk=1)     [C-1]
    aios.pentest.tshark          — pcap read (no live capture)        [C-1]
    aios.pentest.aircrack-ng     — offline dictionary crack           [C-1]

Per ADR-0035 §5, the deprecated Sampling primitive is NOT exposed;
the manifest contains only Tools. Resources and Prompts are deferred
to Sprint 2.
"""

from __future__ import annotations
import json
import os
import subprocess
import shlex
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from . import audit_client as audit_lib
from . import _dispatch as dispatch_mod
from . import pentest as pentest_mod
from . import retention as retention_mod
from . import anchors as anchors_mod
from . import restraint as restraint_mod
from . import verifier as verifier_mod
from . import compliance as compliance_mod

mcp = FastMCP("aiosh-mcp")
SCHEMA_VERSION = "2025-06-18"   # MCP schema version pinned by ADR-0035 §D-2.


# -----------------------------------------------------------------------
# Sprint-0 tools (kept for backward compat; Sprint 0 is shipped).
# Sprint 2 change: every tool now passes through the same classifier →
# PEP → audit dispatch boundary as the pentest wrappers. This prevents
# the agent from reaching a "read-only" tool through a side path that
# lacks classifier provenance or an audit row.
# -----------------------------------------------------------------------


def _recorded_call(
    *,
    tool: str,
    command: str,
    args: dict,
    target: str | None,
    grant_id: str | None,
    fn,
    require_grant: bool = False,
) -> dict:
    """Run a non-pentest MCP function behind the authoritative Sprint-2
    gate and append exactly one result audit row after it returns.

    `dispatch_mod.dispatch()` performs classifier first, then PEP. On
    refusal it already writes the refusal row and returns its audit_id.
    On success this helper calls `commit()` with the classifier fields
    returned by the gate, then attaches that audit_id to the result.
    """
    verdict, _ = dispatch_mod.dispatch(
        tool=tool, command=command, args=args, target=target,
        grant_id=grant_id, require_grant=require_grant,
    )
    if not verdict["ok"]:
        return verdict
    try:
        raw = fn()
        if not isinstance(raw, dict):
            raw = {"ok": True, "result": raw}
        outcome = "ok" if raw.get("ok", True) else "error"
        detail = None if outcome == "ok" else str(raw.get("error", "tool returned ok=false"))
        row = dispatch_mod.commit(
            tool=tool, command=command, args=args, target=target,
            grant_id=grant_id, outcome=outcome, outcome_detail=detail,
            policy_revision=verdict.get("policy_revision"),
            classify_rule_ids=verdict.get("classify_rule_ids"),
            classify_evidence=verdict.get("classify_evidence"),
            classify_overall_verdict=verdict.get("classify_overall_verdict"),
            classify_verdict_reason=verdict.get("classify_verdict_reason"),
        )
        return {**raw, "audit_id": row.id,
                "classifier_policy_revision": verdict.get("policy_revision")}
    except Exception as exc:
        detail = str(exc)
        row = dispatch_mod.commit(
            tool=tool, command=command, args=args, target=target,
            grant_id=grant_id, outcome="error", outcome_detail=detail,
            policy_revision=verdict.get("policy_revision"),
            classify_rule_ids=verdict.get("classify_rule_ids"),
            classify_evidence=verdict.get("classify_evidence"),
            classify_overall_verdict=verdict.get("classify_overall_verdict"),
            classify_verdict_reason=verdict.get("classify_verdict_reason"),
        )
        return {"ok": False, "tool": tool, "error": detail,
                "audit_id": row.id}


@mcp.tool()
def aios_fs_read(path: str, grant_id: str | None = None) -> dict:
    """Read a UTF-8 text file through the classifier/PEP/audit gate.
    The legacy policy still requires an explicit grant and restricts
    reads to `/tmp` or `$HOME/.aios/`."""
    abs_path = str(Path(path).expanduser().resolve())

    def run() -> dict:
        safe_roots = ["/tmp", os.environ.get("HOME", "/tmp") + "/.aios"]
        if not any(abs_path == r or abs_path.startswith(r + "/")
                   for r in safe_roots):
            return {"ok": False,
                    "error": f"path '{abs_path}' outside safe roots",
                    "tool": "aios.fs.read"}
        try:
            data = Path(abs_path).read_text(encoding="utf-8")
            return {"ok": True, "tool": "aios.fs.read", "path": abs_path,
                    "bytes": len(data), "truncated": len(data) > 16384,
                    "content": data[:16384]}
        except FileNotFoundError:
            return {"ok": False, "error": f"file not found: {abs_path}",
                    "tool": "aios.fs.read"}

    return _recorded_call(
        tool="aios.fs.read", command=f"fs.read {abs_path}",
        args={"path": abs_path}, target=abs_path, grant_id=grant_id,
        require_grant=True, fn=run,
    )


@mcp.tool()
def aios_process_list() -> dict:
    """List running processes through the classifier/audit gate."""
    def run() -> dict:
        procs: list[dict] = []
        if os.path.isdir("/proc"):
            for entry in sorted(os.listdir("/proc")):
                if not entry.isdigit():
                    continue
                pid = int(entry)
                try:
                    with open(f"/proc/{pid}/comm") as f:
                        name = f.read().strip()
                except (FileNotFoundError, ProcessLookupError):
                    continue
                procs.append({"pid": pid, "name": name})
        else:
            out = subprocess.check_output(["ps", "-eo", "pid=,comm="], text=True)
            for line in out.splitlines():
                parts = line.strip().split(None, 1)
                if len(parts) == 2:
                    procs.append({"pid": int(parts[0]), "name": parts[1]})
        return {"ok": True, "tool": "aios.process.list",
                "count": len(procs), "processes": procs[:256]}

    return _recorded_call(
        tool="aios.process.list", command="process.list", args={},
        target=None, grant_id=None, fn=run,
    )


@mcp.tool()
def aios_audit_tail(n: int = 10) -> dict:
    """Tail the audit ring through the classifier/audit gate."""
    def run() -> dict:
        with audit_lib.open_db() as conn:
            rows = audit_lib.tail(conn, n)
        return {"ok": True, "tool": "aios.audit.tail", "count": len(rows),
                "rows": [r.to_dict() for r in rows]}

    return _recorded_call(
        tool="aios.audit.tail", command=f"audit.tail {n}", args={"n": n},
        target=None, grant_id=None, fn=run,
    )


@mcp.tool()
def aios_audit_verify(full: bool = False) -> dict:
    """Verify the audit ring through the classifier/audit gate.

    Sprint 3: default verifies the live table anchored at the newest
    rotation checkpoint; full=True additionally replays every archived
    segment file (checksum + chain re-hash) before the live walk."""
    def run() -> dict:
        with audit_lib.open_db() as conn:
            result = audit_lib.verify(conn, full=full)
        return {**result, "tool": "aios.audit.verify", "ok_": result["ok"]}

    return _recorded_call(
        tool="aios.audit.verify", command=f"audit.verify full={full}",
        args={"full": full}, target=None, grant_id=None, fn=run,
    )


# -----------------------------------------------------------------------
# Sprint 3: audit-ring retention tools (ADR-0036 / SPEC-AUDIT-RETENTION).
# -----------------------------------------------------------------------


@mcp.tool()
def aios_release_generate(target_os: str, components: list[str], version: str, grant_id: str | None = None) -> dict:
    """Package an AIOS release ISO through the classifier/audit gate. Requires PEP grant."""
    tool = "aios.release.generate"
    args = {"target_os": target_os, "components": components, "version": version}

    verdict, _ = dispatch_mod.dispatch(
        tool=tool, command=f"release.generate {target_os} {version}", args=args, target=None,
        grant_id=grant_id, require_grant=True,
    )
    if not verdict["ok"]:
        return verdict
    try:
        from .release import generate_release, PackageManifest
        manifest = PackageManifest(target_os=target_os, components=components, version=version)
        path, hash_val = generate_release(
            manifest, actor_id="agent:mcp@aiosh-mcp", constitution_rev=dispatch_mod.active_constitution_rev(),
            grant_id=grant_id, policy_revision=verdict.get("policy_revision"),
            classify_rule_ids=verdict.get("classify_rule_ids"), classify_evidence=verdict.get("classify_evidence"),
            classify_overall_verdict=verdict.get("classify_overall_verdict"), classify_verdict_reason=verdict.get("classify_verdict_reason")
        )
        return {"ok": True, "tool": tool, "path": path, "hash": hash_val, "classifier_policy_revision": verdict.get("policy_revision")}
    except Exception as exc:
        detail = str(exc)
        row = dispatch_mod.commit(
            tool=tool, command=f"release.generate {target_os} {version}", args=args, target=None,
            grant_id=grant_id, outcome="error", outcome_detail=detail,
            policy_revision=verdict.get("policy_revision"), classify_rule_ids=verdict.get("classify_rule_ids"),
            classify_evidence=verdict.get("classify_evidence"), classify_overall_verdict=verdict.get("classify_overall_verdict"),
            classify_verdict_reason=verdict.get("classify_verdict_reason")
        )
        return {"ok": False, "tool": tool, "error": detail, "audit_id": row.id}


@mcp.tool()
def aios_backup_create(target_path: str, include_audit: bool = True, include_memory: bool = False, grant_id: str | None = None) -> dict:
    """Create a system snapshot backup through the classifier/audit gate. Requires PEP grant."""
    tool = "aios.backup.create"
    args = {"target_path": target_path, "include_audit": include_audit, "include_memory": include_memory}

    verdict, _ = dispatch_mod.dispatch(
        tool=tool, command=f"backup.create {target_path}", args=args, target=target_path,
        grant_id=grant_id, require_grant=True,
    )
    if not verdict["ok"]:
        return verdict
    try:
        from .release import create_backup, BackupSnapshot
        snapshot = BackupSnapshot(target_path=target_path, include_audit=include_audit, include_memory=include_memory)
        path = create_backup(
            snapshot, actor_id="agent:mcp@aiosh-mcp", constitution_rev=dispatch_mod.active_constitution_rev(),
            grant_id=grant_id, policy_revision=verdict.get("policy_revision"),
            classify_rule_ids=verdict.get("classify_rule_ids"), classify_evidence=verdict.get("classify_evidence"),
            classify_overall_verdict=verdict.get("classify_overall_verdict"), classify_verdict_reason=verdict.get("classify_verdict_reason")
        )
        return {"ok": True, "tool": tool, "path": path, "classifier_policy_revision": verdict.get("policy_revision")}
    except Exception as exc:
        detail = str(exc)
        row = dispatch_mod.commit(
            tool=tool, command=f"backup.create {target_path}", args=args, target=target_path,
            grant_id=grant_id, outcome="error", outcome_detail=detail,
            policy_revision=verdict.get("policy_revision"), classify_rule_ids=verdict.get("classify_rule_ids"),
            classify_evidence=verdict.get("classify_evidence"), classify_overall_verdict=verdict.get("classify_overall_verdict"),
            classify_verdict_reason=verdict.get("classify_verdict_reason")
        )
        return {"ok": False, "tool": tool, "error": detail, "audit_id": row.id}


# -----------------------------------------------------------------------


@mcp.tool()
def aios_audit_rotate(keep_rows: int = 0, grant_id: str | None = None) -> dict:
    """Seal the oldest live audit rows into an archived segment
    (checkpoint + JSONL archive + bloom filter), keeping the newest
    `keep_rows` rows live. Never destroys entries — rotation is
    archival (Constitution P-2), and the event itself is recorded as
    exactly one `audit.rotate` row in the chain (O-2). Mutates the
    audit store, so an explicit PEP grant scoped to `audit.rotate`
    (or `audit.*`) is required."""
    tool = "audit.rotate"
    args = {"keep_rows": keep_rows}

    verdict, _ = dispatch_mod.dispatch(
        tool=tool, command="audit.rotate", args=args, target=None,
        grant_id=grant_id, require_grant=True,
    )
    if not verdict["ok"]:
        return verdict
    try:
        with dispatch_mod.conn_ctx() as conn:
            result = retention_mod.rotate(
                conn, keep_rows=keep_rows,
                actor="agent", actor_id="agent:mcp@aiosh-mcp",
                grant_token=grant_id,
                constitution_rev=dispatch_mod.active_constitution_rev(),
            )
        if not result.get("ok"):
            # retention.rotate already wrote its own refusal row.
            return {**result, "tool": tool, "gate": "retention",
                    "classifier_policy_revision": verdict.get("policy_revision")}
        return {**result, "tool": tool,
                "classifier_policy_revision": verdict.get("policy_revision")}
    except Exception as exc:
        detail = str(exc)
        row = dispatch_mod.commit(
            tool=tool, command="audit.rotate", args=args, target=None,
            grant_id=grant_id, outcome="error", outcome_detail=detail,
            policy_revision=verdict.get("policy_revision"),
            classify_rule_ids=verdict.get("classify_rule_ids"),
            classify_evidence=verdict.get("classify_evidence"),
            classify_overall_verdict=verdict.get("classify_overall_verdict"),
            classify_verdict_reason=verdict.get("classify_verdict_reason"),
        )
        return {"ok": False, "tool": tool, "error": detail,
                "audit_id": row.id}


@mcp.tool()
def aios_audit_segments() -> dict:
    """List archived audit-ring rotation checkpoints (segment id, row
    range, head hash, archive path + sha256, bloom parameters)."""
    def run() -> dict:
        with audit_lib.open_db() as conn:
            segs = retention_mod.list_segments(conn)
        return {"ok": True, "tool": "aios.audit.segments",
                "count": len(segs), "segments": segs}

    return _recorded_call(
        tool="aios.audit.segments", command="audit.segments", args={},
        target=None, grant_id=None, fn=run,
    )


@mcp.tool()
def aios_audit_seen(hash_hex: str, exact: bool = False) -> dict:
    """Membership query over the audit history: was this row hash ever
    logged? Checks the live ring, then per-segment bloom filters
    (no false negatives; positives may need --exact confirmation by
    scanning the archive files)."""
    def run() -> dict:
        with audit_lib.open_db() as conn:
            result = retention_mod.seen(conn, hash_hex, exact=exact)
        return {"ok": True, "tool": "aios.audit.seen", **result}

    return _recorded_call(
        tool="aios.audit.seen", command=f"audit.seen {hash_hex}",
        args={"hash": hash_hex, "exact": exact},
        target=None, grant_id=None, fn=run,
    )


# -----------------------------------------------------------------------
# Proof of Restraint: Chain Anchoring & Completeness Checkpoints (Component 3)
# -----------------------------------------------------------------------


@mcp.tool()
def aios_anchor_create(key_hex: str | None = None, grant_id: str | None = None) -> dict:
    """Create an Ed25519-signed anchor for current audit chain head outside audit.db.
    Appends anchor to $AIOSH_HOME/anchors/anchors.jsonl.
    Key is loaded from key_hex parameter or AIOSH_ANCHOR_KEY environment variable.
    """
    tool = "aios.anchor.create"
    command = "anchor.create"
    args = {"has_key": bool(key_hex or os.environ.get("AIOSH_ANCHOR_KEY"))}

    def run() -> dict:
        priv_key = key_hex or os.environ.get("AIOSH_ANCHOR_KEY")
        if not priv_key:
            return {"ok": False, "error": "No anchor signing key provided (set AIOSH_ANCHOR_KEY or pass key_hex)"}
        with audit_lib.open_db() as conn:
            head = audit_lib.head(conn)
            if not head:
                return {"ok": False, "error": "Audit ring is empty; cannot anchor genesis without rows"}
            seq = head.id
            head_hash = head.hash
            ts = head.ts

        anchor = anchors_mod.sign_checkpoint(seq=seq, head_hash=head_hash, timestamp=ts, private_key_hex=priv_key)
        aiosh_home = Path(os.environ.get("AIOSH_HOME", f"{os.environ.get('HOME', '/tmp')}/.aios"))
        anchors_path = aiosh_home / "anchors" / "anchors.jsonl"
        anchors_mod.append_anchor(anchor, anchors_path)
        return {"ok": True, "tool": tool, "anchor": anchor.to_dict(), "path": str(anchors_path)}

    return _recorded_call(
        tool=tool, command=command, args=args,
        target=None, grant_id=grant_id, fn=run,
    )


@mcp.tool()
def aios_anchor_verify(pubkey: str | None = None) -> dict:
    """Verify the audit chain against external signed completeness anchors in $AIOSH_HOME/anchors/anchors.jsonl."""
    tool = "aios.anchor.verify"
    command = "anchor.verify"
    args = {"pubkey": pubkey}

    def run() -> dict:
        aiosh_home = Path(os.environ.get("AIOSH_HOME", f"{os.environ.get('HOME', '/tmp')}/.aios"))
        anchors_path = aiosh_home / "anchors" / "anchors.jsonl"
        anchors = anchors_mod.load_anchors(anchors_path)
        if not anchors:
            return {"ok": True, "tool": tool, "anchors_count": 0, "verified": True, "message": "No anchors found to verify"}

        trusted = pubkey or os.environ.get("AIOSH_ANCHOR_PUBKEY")
        with audit_lib.open_db() as conn:
            cursor = conn.execute("SELECT id, hash FROM audit_ring ORDER BY id ASC")
            chain_rows = [{"id": r[0], "hash": r[1]} for r in cursor.fetchall()]

        valid, err = anchors_mod.verify_chain_against_anchors(chain_rows, anchors, trusted_pubkey=trusted)
        return {
            "ok": valid,
            "tool": tool,
            "anchors_count": len(anchors),
            "verified": valid,
            "error": err,
        }

    return _recorded_call(
        tool=tool, command=command, args=args,
        target=None, grant_id=None, fn=run,
    )


# -----------------------------------------------------------------------
# Proof of Restraint: Restraint Proof Generator (Component 4)
# -----------------------------------------------------------------------


@mcp.tool()
def aios_restraint_prove(
    grant_id: str,
    window_start: str,
    window_end: str,
    anchors_path: str | None = None,
    caller_grant_id: str | None = None,
) -> dict:
    """Generate a self-contained RestraintProofPackage proving negative attestation
    (non-use) of grant_id during the interval [window_start, window_end]."""
    tool = "aios.restraint.prove"
    command = f"restraint.prove {grant_id}"
    args = {"grant_id": grant_id, "window_start": window_start, "window_end": window_end}

    def run() -> dict:
        try:
            with audit_lib.open_db() as conn:
                proof = restraint_mod.generate_restraint_proof(
                    conn=conn,
                    grant_id=grant_id,
                    window_start=window_start,
                    window_end=window_end,
                    anchors_path=anchors_path,
                )
            return {
                "ok": True,
                "tool": tool,
                "proof": proof.to_dict(),
            }
        except ValueError as exc:
            return {"ok": False, "tool": tool, "error": str(exc)}
        except Exception as exc:
            return {"ok": False, "tool": tool, "error": f"INTERNAL_ERROR: {str(exc)}"}

    return _recorded_call(
        tool=tool, command=command, args=args,
        target=grant_id, grant_id=caller_grant_id, fn=run,
    )


@mcp.tool()
def aios_restraint_verify(
    proof: dict | str,
    trusted_pubkeys: list[str] | str,
    caller_grant_id: str | None = None,
) -> dict:
    """Verify a self-contained RestraintProofPackage purely mathematically against trusted Ed25519 public keys."""
    tool = "aios.restraint.verify"
    command = "restraint.verify"
    keys = [trusted_pubkeys] if isinstance(trusted_pubkeys, str) else trusted_pubkeys
    args = {"trusted_keys_count": len(keys)}

    def run() -> dict:
        try:
            res = verifier_mod.verify_restraint_proof(proof, keys)
            return {
                "ok": res.valid,
                "tool": tool,
                "result": res.to_dict(),
            }
        except Exception as exc:
            return {"ok": False, "tool": tool, "error": f"INTERNAL_ERROR: {str(exc)}"}

    return _recorded_call(
        tool=tool, command=command, args=args,
        target=None, grant_id=caller_grant_id, fn=run,
    )





# -----------------------------------------------------------------------
# -----------------------------------------------------------------------
# T-00043 SCAFFOLD — Task Ledger Control MCP surface on the reference
# substrate (spec T-00042). Bodies fail loudly until T-00044; the
# registration itself is inert until called. Contract mirrors the Rust
# `aios.task` exactly (gate string "aios.task", per-action grant
# policy, caps, envelope shapes) so ONE grant works across substrates.
# -----------------------------------------------------------------------

def _env_int(name: str, default: int, lo: int) -> int:
    """T-00054: AIOSH_LEDGER_* env override w/ loud errors (parity with
    aiosh-core/src/ledger_config.rs)."""
    import os as _os
    raw = _os.environ.get(name)
    if raw is None:
        return default
    try:
        v = int(raw)
    except ValueError:
        raise SystemExit(f"invalid {name}='{raw}': not an integer")
    if v < lo:
        raise SystemExit(f"invalid {name}='{raw}': must be >= {lo}")
    return v


MAX_TASK_TEXT = _env_int("AIOSH_LEDGER_MAX_TEXT", 4096, 64)
MAX_TASK_EVIDENCE = _env_int("AIOSH_LEDGER_MAX_EVIDENCE_ITEMS", 16, 1)

_TASK_READ_ONLY = {"status", "check", "metrics", "validate"}
_TASK_ACTIONS = {"status", "check", "metrics", "validate", "done", "block",
                 "unblock", "skip", "rebuild"}


def _task_metrics(*, grant_id: str | None = None) -> dict:
    """T-00084: consolidated observability snapshot (stable ADDITIVE-ONLY
    key set, mirroring Rust TaskCall::build_metrics).

    Baseline-repair (found by matrix case M10, 2026-08-22): this action
    previously SHORT-CIRCUITED before the dispatch gate, so (a) an
    explicitly-presented expired/revoked grant was NOT rejected
    (breaking the M7 fail-closed semantics for one action), and (b) no
    audit row was ever written (O-2 violation; the Rust surface commits
    exactly one row per metrics call). It now routes through the SAME
    classifier -> PEP -> audit gate as every other aios.task action and
    attaches the committed row id as `audit_id`."""

    def _env_int(name: str, default: int) -> int:
        raw = os.environ.get(name)
        return int(raw) if raw else default

    args_json = {"action": "metrics"}
    verdict, _row = dispatch_mod.dispatch(
        tool="aios.task", command="task.metrics", args=args_json,
        target=None, grant_id=grant_id, require_grant=False,
        actor_id="agent:mcp@aiosh-mcp", actor="agent:mcp",
    )
    cls_kwargs = {
        "policy_revision": verdict.get("policy_revision"),
        "classify_rule_ids": verdict.get("classify_rule_ids"),
        "classify_evidence": verdict.get("classify_evidence"),
        "classify_overall_verdict": verdict.get("classify_overall_verdict"),
        "classify_verdict_reason": verdict.get("classify_verdict_reason"),
    }
    if not verdict["ok"]:
        return {"ok": False, "action": "metrics",
                "gate": verdict.get("gate"),
                "reason": verdict.get("reason"),
                "audit_id": verdict.get("audit_id")}
    try:
        tl = _load_task_ledger()
        tasks = tl.load_state()
        conn = audit_lib.open_db()
        try:
            rows = conn.execute("SELECT COUNT(*) FROM audit_ring").fetchone()[0]
            v = audit_lib.verify_live(conn)
            verify_ok = bool(v.get("ok"))
            head = audit_lib.head_hash(conn)[:12]
        finally:
            conn.close()
        data = {
            "tasks": {k: tasks.get(k) for k in (
                "total_tasks", "completed", "blocked", "skipped",
                "next_task", "last_event_seq", "last_completed_at")},
            "audit": {"rows": rows, "verify_ok": verify_ok,
                      "head_hash_prefix": head},
            "config": {
                "lock_timeout_secs": _env_int("AIOSH_LEDGER_LOCK_TIMEOUT_SECS", 5),
                "max_ledger_bytes": _env_int("AIOSH_LEDGER_MAX_LEDGER_BYTES", 64 * 1024 * 1024),
                "max_events_bytes": _env_int("AIOSH_LEDGER_MAX_EVENTS_BYTES", 16 * 1024 * 1024),
                "max_state_bytes": _env_int("AIOSH_LEDGER_MAX_STATE_BYTES", 4 * 1024 * 1024),
                "max_text": MAX_TASK_TEXT,
                "max_evidence_items": MAX_TASK_EVIDENCE,
            },
        }
    except Exception as exc:  # honest error row, never silent
        detail = str(exc)
        r = dispatch_mod.commit(
            tool="aios.task", command="task.metrics", args=args_json,
            target=None, grant_id=grant_id, outcome="error",
            outcome_detail=detail, **cls_kwargs)
        return {"ok": False, "action": "metrics", "error": detail,
                "audit_id": r.id}
    r = dispatch_mod.commit(
        tool="aios.task", command="task.metrics", args=args_json,
        target=None, grant_id=grant_id, outcome="ok", outcome_detail=None,
        **cls_kwargs)
    return {"ok": True, "action": "metrics", "data": data,
            "audit_id": r.id,
            "classifier_policy_revision": verdict.get("policy_revision")}


_TASK_LEDGER_MOD = None


def _load_task_ledger():
    """Import the legacy ledger module once (cached), honoring
    AIOSH_TASKS_DIR (its module-level paths bind from the environment
    at import). T-00048: cached instead of re-executing per call."""
    global _TASK_LEDGER_MOD
    if _TASK_LEDGER_MOD is None:
        import importlib.util as _ilu
        tl_path = Path(__file__).resolve().parents[3] / "tools" / "task_ledger.py"
        spec = _ilu.spec_from_file_location("aiosh_task_ledger", str(tl_path))
        mod = _ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _TASK_LEDGER_MOD = mod
    return _TASK_LEDGER_MOD


def _validate_task_args(*, action: str, task_id, note, reason, evidence) -> None:
    """Mirror of Rust TaskCall::validate + parse_args caps (spec §2).

    Raises ValueError on structural/semantic violations; the caller
    converts to the standard {ok:false} envelope BEFORE any gate or
    disk interaction."""
    if action not in _TASK_ACTIONS:
        raise ValueError(f"unknown action '{action}'")
    needs_id = action not in {"status", "check", "rebuild", "metrics", "validate"}
    if needs_id and task_id is None:
        raise ValueError(f"action '{action}' requires 'task_id'")
    if not needs_id and task_id is not None:
        raise ValueError(f"action '{action}' does not take 'task_id'")
    if task_id is not None:
        if isinstance(task_id, bool) or task_id < 1:
            raise ValueError("'task_id' must be a positive integer >= 1")

    def _bounded(field: str, val):
        if val is None:
            return None
        if not isinstance(val, str) or len(val) == 0:
            raise ValueError(f"'{field}' must be a non-empty string")
        if len(val) > MAX_TASK_TEXT:
            raise ValueError(f"'{field}' exceeds {MAX_TASK_TEXT} bytes")
        return val

    if action == "done":
        if _bounded("note", note) is None:
            raise ValueError("action 'done' requires a non-empty 'note'")
    if action in {"block", "unblock", "skip"}:
        if _bounded("reason", reason) is None:
            raise ValueError(f"action '{action}' requires a non-empty 'reason'")
    if evidence is not None:
        if not isinstance(evidence, list) or any(not isinstance(e, str) for e in evidence):
            raise ValueError("'evidence' must be a list of strings")
        if len(evidence) > MAX_TASK_EVIDENCE:
            raise ValueError(f"'evidence' exceeds {MAX_TASK_EVIDENCE} items")
        for e in evidence:
            if len(e) > MAX_TASK_TEXT:
                raise ValueError(f"'evidence' item exceeds {MAX_TASK_TEXT} bytes")


def _run_task_action(mod, *, action: str, task_id, note, reason, evidence) -> dict:
    """Dispatch into the legacy ledger module (same semantics as the
    Rust TaskCall::execute_with)."""
    if action == "status":
        return mod.load_state()
    if action == "check":
        return mod.assert_ledger_invariants()
    if action == "validate":
        return mod.validate_state()
    if action == "done":
        return mod.complete_task(task_id, note=note or "", evidence=evidence or [])
    if action == "block":
        return mod.block_task(task_id, reason)
    if action == "unblock":
        return mod.unblock_task(task_id, reason)
    if action == "skip":
        return mod.skip_task(task_id, reason)
    return mod.rebuild_state()


@mcp.tool()
def aios_task(
    action: str,
    task_id: int | None = None,
    note: str | None = None,
    reason: str | None = None,
    evidence: list[str] | None = None,
    grant_id: str | None = None,
) -> dict:
    """Task Ledger Control: query or advance the AIOS master task
    ledger. Read-only: status, check, metrics, validate. Consequential
    (PEP grant scoped to \"aios.task\" required): done, block, unblock,
    skip, rebuild. Mirrors the Rust `aios.task` tool contract exactly."""
    # Structural/semantic validation FIRST (no gate interaction).
    try:
        _validate_task_args(action=action, task_id=task_id, note=note,
                            reason=reason, evidence=evidence)
    except ValueError as exc:
        return {"ok": False, "action": action, "error": str(exc)}

    if action == "metrics":
        return _task_metrics(grant_id=grant_id)

    requires_grant = action not in _TASK_READ_ONLY
    args_json = {"action": action, "task_id": task_id, "note": note,
                 "reason": reason, "evidence": evidence}
    verdict, _row = dispatch_mod.dispatch(
        tool="aios.task", command=f"task.{action}", args=args_json,
        target=None, grant_id=grant_id, require_grant=requires_grant,
        actor_id="agent:mcp@aiosh-mcp", actor="agent:mcp",
    )
    if not verdict["ok"]:
        return {"ok": False, "action": action, "gate": verdict.get("gate"),
                "reason": verdict.get("reason"), "audit_id": verdict.get("audit_id")}

    tl = None
    try:
        # T-00048: the loader is INSIDE the guarded section — if it
        # fails (missing/corrupt module), we still write an honest
        # error row instead of leaking a framework exception.
        tl = _load_task_ledger()
        raw = _run_task_action(
            tl, action=action, task_id=task_id, note=note,
            reason=reason, evidence=evidence,
        )
    except Exception as exc:  # honest error row, never silent
        detail = str(exc)
        r = dispatch_mod.commit(
            tool="aios.task", command=f"task.{action}", args=args_json,
            target=None, grant_id=grant_id, outcome="error",
            outcome_detail=detail,
            policy_revision=verdict.get("policy_revision"),
            classify_rule_ids=verdict.get("classify_rule_ids"),
            classify_evidence=verdict.get("classify_evidence"),
            classify_overall_verdict=verdict.get("classify_overall_verdict"),
            classify_verdict_reason=verdict.get("classify_verdict_reason"),
        )
        return {"ok": False, "action": action, "error": detail, "audit_id": r.id}

    # Bare payloads get the standard envelope; mutations already carry ok.
    out = ({**raw, "action": action} if isinstance(raw, dict) and "ok" in raw
           else {"ok": True, "action": action, "data": raw})
    r = dispatch_mod.commit(
        tool="aios.task", command=f"task.{action}", args=args_json,
        target=None, grant_id=grant_id, outcome="ok",
        outcome_detail=None,
        policy_revision=verdict.get("policy_revision"),
        classify_rule_ids=verdict.get("classify_rule_ids"),
        classify_evidence=verdict.get("classify_evidence"),
        classify_overall_verdict=verdict.get("classify_overall_verdict"),
        classify_verdict_reason=verdict.get("classify_verdict_reason"),
    )
    out["audit_id"] = r.id
    # Parity with Rust dispatch::recorded_call: every gated action
    # response carries the policy revision that decided it.
    out["classifier_policy_revision"] = verdict.get("policy_revision")
    return out


# -----------------------------------------------------------------------
# Compliance Mapping: MCP/API surface (Component 7) — T-02896 IMPLEMENTATION
# Contract: docs/tasks/evidence/T-02894-spec.md (normative).
# Every call runs behind _recorded_call: exactly one audit row per call
# (§7); register/status/init are grant-gated (§8). Domain errors surface
# as the §4 envelope {ok:false, action, error, audit_id} — never silent.
# -----------------------------------------------------------------------


@mcp.tool()
def aios_compliance(
    action: str,
    id: str | None = None,
    framework: str | None = None,
    status: str | None = None,
    control_id: str | None = None,
    target_type: str | None = None,
    target_ref: str | None = None,
    threat_ids: list[str] | None = None,
    mitigation_summary: str | None = None,
    tags: list[str] | None = None,
    reason: str | None = None,
    gate_id: str | None = None,
    grant_id: str | None = None,
    query: str | None = None,
) -> dict:
    """Compliance Mapping control surface (T-02894-spec.md §2): action dispatch
    over the compliance catalog. Actions: list | show | register | status |
    assess | check-pep | init | stats | doc-list | doc-get | doc-search. Read actions need no grant; register/status/init
    are state-changing and require a capability grant via grant_id.

    The store is selected by the shared configuration ladder
    (T-02904-spec.md §3.2): `AIOSH_COMPLIANCE_MAP_PATH` env, else the config
    file named by `AIOSH_COMPLIANCE_CONFIG` (default
    `docs/compliance_config.json`), else `docs/compliance_map.json`."""
    tool = "aios.compliance"
    command = f"compliance {action}"
    # Bounded audit args (spec §7): drop Nones, truncate strings/lists at the
    # standard 8192-byte limit — never persist unbounded raw input.
    _raw = {"action": action, "id": id, "framework": framework, "status": status,
            "control_id": control_id, "target_type": target_type,
            "target_ref": target_ref, "threat_ids": threat_ids,
            "mitigation_summary": mitigation_summary, "tags": tags,
            "reason": reason, "gate_id": gate_id, "query": query}

    def _clip(v):
        if isinstance(v, str):
            return v if len(v) <= 8192 else v[:8192] + "…(truncated)"
        if isinstance(v, list):
            return [_clip(x) for x in v[:32]]
        return v

    args = {k: _clip(v) for k, v in _raw.items() if v is not None}

    def run() -> dict:
        try:
            return compliance_mod.execute(
                action=action, id=id, framework=framework, status=status,
                control_id=control_id, target_type=target_type,
                target_ref=target_ref, threat_ids=threat_ids,
                mitigation_summary=mitigation_summary, tags=tags,
                reason=reason, gate_id=gate_id, grant_id=grant_id,
                query=query,
            )
        except ValueError as exc:
            # Spec §4 envelope; _recorded_call turns ok=false into the single
            # outcome="error" audit row.
            return {"ok": False, "action": action, "error": str(exc)}

    return _recorded_call(
        tool=tool, command=command, args=args, target=None,
        grant_id=grant_id, fn=run,
        require_grant=action in compliance_mod.WRITE_ACTIONS,
    )


# Sprint 1: register Pillar A pentest wrapper set.
# Each tool routes through `_dispatch.dispatch()` to enforce PEP + audit.
# -----------------------------------------------------------------------
pentest_mod.register_pentest_tools(mcp)

# -----------------------------------------------------------------------
# Phase 0: Register Release Packaging & Backup endpoints
# -----------------------------------------------------------------------
from . import release as release_mod
release_mod.register_release_tools(mcp)

# -----------------------------------------------------------------------
# Phase 2: Register Incident Response Runbooks & RustSec Scanning MCP tools
# -----------------------------------------------------------------------
from . import incident_runbook_mcp as incident_runbook_mcp_mod
incident_runbook_mcp_mod.register_runbook_tools(mcp)

# -----------------------------------------------------------------------
# Phase 3: Register AI Control Plane MCP Server Core diagnostic tools
# -----------------------------------------------------------------------
from . import mcp_server_core_data_model as mcp_server_core_data_model_mod
mcp_server_core_data_model_mod.register_mcp_core_tools(mcp)

from . import mcp_server_core_service as mcp_server_core_service_mod
mcp_server_core_service_mod.register_mcp_service_tools(mcp)

from . import mcp_server_core_api as mcp_server_core_api_mod
mcp_server_core_api_mod.register_mcp_api_tools(mcp)

from . import mcp_server_core_config as mcp_server_core_config_mod
mcp_server_core_config_mod.register_mcp_config_tools(mcp)

from . import mcp_server_core_tests as mcp_server_core_tests_mod
mcp_server_core_tests_mod.register_mcp_tests_tools(mcp)

from . import mcp_server_core_policy as mcp_server_core_policy_mod
mcp_server_core_policy_mod.register_mcp_policy_tools(mcp)

from . import mcp_server_core_observability as mcp_server_core_observability_mod
mcp_server_core_observability_mod.register_mcp_observability_tools(mcp)

from . import mcp_server_core_doc as mcp_server_core_doc_mod
mcp_server_core_doc_mod.register_mcp_doc_tools(mcp)

from . import mcp_server_core_recovery as mcp_server_core_recovery_mod
mcp_server_core_recovery_mod.register_mcp_recovery_tools(mcp)

from . import model_backend_adapters_data_model as model_backend_adapters_data_model_mod
model_backend_adapters_data_model_mod.register_model_adapter_tools(mcp)

from . import model_backend_adapters_service as model_backend_adapters_service_mod
model_backend_adapters_service_mod.register_model_service_tools(mcp)

from . import model_backend_adapters_api as model_backend_adapters_api_mod
model_backend_adapters_api_mod.register_model_backend_tools(mcp)

from . import model_backend_adapters_observability as model_backend_adapters_observability_mod
model_backend_adapters_observability_mod.register_model_observability_tools(mcp)

from . import model_backend_adapters_doc as model_backend_adapters_doc_mod
model_backend_adapters_doc_mod.register_model_doc_tools(mcp)

from . import model_backend_adapters_recovery as model_backend_adapters_recovery_mod
model_backend_adapters_recovery_mod.register_model_recovery_tools(mcp)

from . import agent_loop_data_model as agent_loop_data_model_mod
agent_loop_data_model_mod.register_agent_loop_data_model_tools(mcp)

from . import agent_loop_service as agent_loop_service_mod
agent_loop_service_mod.register_agent_loop_service_tools(mcp)

# T-03368: read-only tool catalog (canonical names, aliases, taxonomy).
from . import tool_registry_data_model as tool_registry_data_model_mod
tool_registry_data_model_mod.register_tool_registry_tools(mcp)

# T-03396: registry decision/stats tools, then catalog-driven annotations for every served tool. The
# annotation pass runs after all registrations and can only make a tool look more careful (TOOLAPI-INV2).
from . import tool_registry_api as tool_registry_api_mod
tool_registry_api_mod.register_tool_registry_api_tools(mcp)
tool_registry_api_mod.apply_catalog_annotations(mcp)









# -----------------------------------------------------------------------
# Entrypoint: `python -m aiosh_mcp.server` over stdio transport.
# -----------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run(transport="stdio")
