"""Audit ring client — reads and writes the same SQLite WAL audit ring
aiosh-cli writes.

Keeps a single source of truth for "what did the system do?". Both the
CLI surface and the MCP surface emit rows to this same DB; both can read
it back; both can verify the chain.

Canonical JSON / chain-hash rules (cross-substrate contract):
    proto  = { ts, actor, actor_id, tool, command, args, target,
               outcome, outcome_detail, constitution_rev, grant_token,
               c_flags, prev_hash }
    hash   = sha256( prev_hash || canonical_json(proto) )
    row    = proto + { "id": autoincrement, "hash": hash }
This must stay byte-identical to `code/aiosh-cli/src/audit.ts:canonicalJson`
+ `AuditRing.write`. Verified by `tests/test_smoke.py`.
"""

from __future__ import annotations
import datetime as dt
import hashlib
import ipaddress
import json
import os
import sqlite3
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


GENESIS = "0" * 64


def canonical(obj: Any) -> str:
    """Stable JSON serializer: sorted keys, no whitespace.
    None values are kept as null (matching `canonicalJson()` in
    audit.ts which converts undefined to null). This keeps the
    cross-substrate invariant end-to-end."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def utcnow_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass(frozen=True)
class AuditRow:
    id: int
    ts: str
    actor: str
    actor_id: str
    tool: str
    command: str
    args: dict[str, Any]
    target: str | None
    outcome: str
    outcome_detail: str | None
    constitution_rev: str | None
    grant_token: str | None
    c_flags: dict[str, bool]
    policy_revision: str | None = None
    classify_rule_ids: list[str] | None = None
    classify_evidence: dict[str, list[str]] | None = None
    classify_overall_verdict: str | None = None
    classify_verdict_reason: str | None = None
    prev_hash: str = ""
    hash: str = ""

    @classmethod
    def from_sql(cls, row: sqlite3.Row) -> "AuditRow":
        # Sprint 2: classifier columns are nullable on old rows. We
        # include them in the dataclass only when present so that the
        # verify() recomputed proto omits them (matching how the row
        # was originally hashed).
        rule_ids = None
        ev = row["classify_rule_ids_json"] if "classify_rule_ids_json" in row.keys() else None
        if ev is not None:
            try: rule_ids = json.loads(ev)
            except Exception: rule_ids = None
        evd = row["classify_evidence_json"] if "classify_evidence_json" in row.keys() else None
        evidence = None
        if evd is not None:
            try: evidence = json.loads(evd)
            except Exception: evidence = None
        verdict = row["classify_overall_verdict"] if "classify_overall_verdict" in row.keys() else None
        reason = row["classify_verdict_reason"] if "classify_verdict_reason" in row.keys() else None
        policy_rev = row["policy_revision"] if "policy_revision" in row.keys() else None
        return cls(
            id=row["id"],
            ts=row["ts"],
            actor=row["actor"],
            actor_id=row["actor_id"],
            tool=row["tool"],
            command=row["command"],
            args=json.loads(row["args_json"]),
            target=row["target"],
            outcome=row["outcome"],
            outcome_detail=row["outcome_detail"],
            constitution_rev=row["constitution_rev"],
            grant_token=row["grant_token"],
            c_flags={
                "c1": bool(row["c1"]),
                "c2": bool(row["c2"]),
                "c3": bool(row["c3"]),
                "c4": bool(row["c4"]),
            },
            policy_revision=policy_rev,
            classify_rule_ids=rule_ids,
            classify_evidence=evidence,
            classify_overall_verdict=verdict,
            classify_verdict_reason=reason,
            prev_hash=row["prev_hash"],
            hash=row["hash"],
        )

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "ts": self.ts,
            "actor": self.actor,
            "actor_id": self.actor_id,
            "tool": self.tool,
            "command": self.command,
            "args": self.args,
            "target": self.target,
            "outcome": self.outcome,
            "outcome_detail": self.outcome_detail,
            "constitution_rev": self.constitution_rev,
            "grant_token": self.grant_token,
            "c_flags": self.c_flags,
            "prev_hash": self.prev_hash,
            "hash": self.hash,
        }
        # Sprint 2: only include classifier fields when present, so the
        # proto that callers see (e.g. tests comparing row-by-row) mirrors
        # what was actually hashed.
        if self.policy_revision is not None:
            d["policy_revision"] = self.policy_revision
        if self.classify_rule_ids is not None:
            d["classify_rule_ids"] = self.classify_rule_ids
        if self.classify_evidence is not None:
            d["classify_evidence"] = self.classify_evidence
        if self.classify_overall_verdict is not None:
            d["classify_overall_verdict"] = self.classify_overall_verdict
        if self.classify_verdict_reason is not None:
            d["classify_verdict_reason"] = self.classify_verdict_reason
        return d


def default_db_path() -> str:
    base = os.environ.get("AIOSH_HOME", f"{os.environ.get('HOME', '/tmp')}/.aios")
    return f"{base}/audit.db"


def open_db(path: str | None = None) -> sqlite3.Connection:
    p = path or default_db_path()
    Path(p).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(p)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    # MCP may be the first process to touch AIOSH_HOME. Initialize the
    # shared audit table before any tool tries to dispatch/audit. This
    # is idempotent and remains compatible with the TypeScript schema.
    ensure_audit_schema(conn)
    return conn


def tail(conn: sqlite3.Connection, n: int = 10) -> list[AuditRow]:
    n = max(1, min(n, 1024))
    cur = conn.execute(
        "SELECT * FROM audit_ring ORDER BY id DESC LIMIT ?", (n,))
    return [AuditRow.from_sql(r) for r in reversed(list(cur))]


def head(conn: sqlite3.Connection) -> AuditRow | None:
    """Return the newest AuditRow in the live table, or None if empty."""
    cur = conn.execute("SELECT * FROM audit_ring ORDER BY id DESC LIMIT 1")
    r = cur.fetchone()
    return AuditRow.from_sql(r) if r else None


def verify_live(conn: sqlite3.Connection, anchor: str | None = None) -> dict[str, Any]:
    """Verify the live (non-archived) portion of the audit ring.

    The chain anchor for the live segment is the newest segment
    checkpoint's head_hash when segments exist (Sprint 3 rotation), or
    GENESIS for a pristine ring. Rows after a rotation chain from the
    checkpoint, not from genesis.
    """
    if anchor is None:
        anchor = latest_segment_head(conn) or GENESIS
    cur = conn.execute("SELECT * FROM audit_ring ORDER BY id ASC")
    prev = anchor
    i = 0
    for row_raw in cur:
        row = AuditRow.from_sql(row_raw)
        if row.prev_hash != prev:
            return {"ok": False, "checked": i, "broken_at": row.id}
        # Sprint 2: classifier fields are conditionally included in the
        # recomputed proto iff non-null on the row. Old rows from
        # Sprint 0/1/1.5 have NULL there because their hash was computed
        # without them — this preserves the canonical-JSON invariant
        # across the Sprint-2 schema migration. Cross-language proof:
        # tests/test_smoke.py + tests/test_agent_smoke.py.
        proto = _hash_proto(row)
        expected = sha256_hex(prev + canonical(proto))
        if expected != row.hash:
            return {"ok": False, "checked": i, "broken_at": row.id}
        prev = row.hash
        i += 1
    return {"ok": True, "checked": i, "broken_at": None, "anchor": anchor}


def _hash_proto(row: AuditRow) -> dict[str, Any]:
    """Rebuild the hashed proto dict for a row (same shape as at write time)."""
    proto: dict[str, Any] = {
        "ts": row.ts,
        "actor": row.actor,
        "actor_id": row.actor_id,
        "tool": row.tool,
        "command": row.command,
        "args": row.args,
        "target": row.target,
        "outcome": row.outcome,
        "outcome_detail": row.outcome_detail,
        "constitution_rev": row.constitution_rev,
        "grant_token": row.grant_token,
        "c_flags": row.c_flags,
        "prev_hash": row.prev_hash,
    }
    if row.policy_revision is not None:
        proto["policy_revision"] = row.policy_revision
    if row.classify_rule_ids is not None:
        proto["classify_rule_ids"] = row.classify_rule_ids
    if row.classify_evidence is not None:
        proto["classify_evidence"] = row.classify_evidence
    if row.classify_overall_verdict is not None:
        proto["classify_overall_verdict"] = row.classify_overall_verdict
    if row.classify_verdict_reason is not None:
        proto["classify_verdict_reason"] = row.classify_verdict_reason
    return proto


def verify(conn: sqlite3.Connection, full: bool = False,
           archive_root: str | None = None) -> dict[str, Any]:
    """Verify the audit ring.

    Default (full=False) verifies only the live table against the latest
    segment checkpoint anchor. With full=True, archived segments are
    replayed first (file checksum + chain re-hash), then the live table.
    """
    if full:
        # Imported here to avoid a circular import at module load time.
        from . import retention
        return retention.verify_full(conn, archive_root=archive_root)
    return verify_live(conn)


# ----------------------------------------------------------------------
# write() and grant helpers — Sprint 1 (Pillar C pentest tools).
# ----------------------------------------------------------------------

# Schema for `pep_grants` matches `code/aiosh-cli/src/pep.ts:PepStore.init_()`.
# In Sprint 1 we only need to read grants for the gate; CLI is the canonical
# issuer, but a Python issuer is provided for AI-driven use cases.
_PEP_SCHEMA = """
CREATE TABLE IF NOT EXISTS pep_grants (
  grant_id          TEXT PRIMARY KEY,
  issued_at         TEXT NOT NULL,
  expires_at        TEXT NOT NULL,
  issued_to         TEXT NOT NULL,
  constitution_rev  TEXT NOT NULL,
  scope_json        TEXT NOT NULL,
  scope_hash        TEXT NOT NULL,
  revoked_at        TEXT
);
CREATE INDEX IF NOT EXISTS idx_grants_active
  ON pep_grants(issued_to) WHERE revoked_at IS NULL;
"""


def ensure_pep_schema(conn: sqlite3.Connection) -> None:
    """Create the `pep_grants` table if it does not exist (idempotent).
    The aiosh-cli creates this when its `aiosh grant create` runs; however,
    if the MCP server is used as the first writer (e.g. in tests), we still
    need the table to be present so that the grant gate can read it."""
    conn.executescript(_PEP_SCHEMA)
    conn.commit()


def _segments_table_exists(conn: sqlite3.Connection) -> bool:
    cur = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_segments'"
    )
    return cur.fetchone() is not None


def latest_segment_head(conn: sqlite3.Connection) -> str | None:
    """Return the head hash of the newest archived segment, if any."""
    if not _segments_table_exists(conn):
        return None
    cur = conn.execute(
        "SELECT head_hash FROM audit_segments ORDER BY segment_id DESC LIMIT 1"
    )
    row = cur.fetchone()
    return row[0] if row else None


def head_hash(conn: sqlite3.Connection) -> str:
    cur = conn.execute("SELECT hash FROM audit_ring ORDER BY id DESC LIMIT 1")
    row = cur.fetchone()
    if row:
        return row[0]
    return latest_segment_head(conn) or GENESIS


def load_grant(conn: sqlite3.Connection, grant_id: str) -> dict[str, Any] | None:
    """Returns the grant record or None if unknown/revoked/expired.
    The CLI is the canonical issuer; the MCP gate just reads."""
    cur = conn.execute(
        "SELECT * FROM pep_grants WHERE grant_id = ?", (grant_id,))
    row = cur.fetchone()
    if not row:
        return None
    if row["revoked_at"] is not None:
        return None
    keys = row.keys()
    return {
        "grant_id": row["grant_id"],
        "issued_at": row["issued_at"],
        "expires_at": row["expires_at"],
        "issued_to": row["issued_to"],
        "constitution_rev": row["constitution_rev"],
        "scope": json.loads(row["scope_json"]),
        "single_use": bool(row["single_use"]) if "single_use" in keys and row["single_use"] is not None else True,
        "redeemed_at": row["redeemed_at"] if "redeemed_at" in keys else None,
    }


def tool_glob_match(tool: str, globs: Iterable[str]) -> bool:
    """Replicates `code/aiosh-cli/src/pep.ts:toolGlobMatch()` in Python."""
    globs = list(globs)
    if not globs:
        return False
    for glob in globs:
        if glob == tool:
            return True
        if glob.endswith(".*") and tool.startswith(glob[:-2]):
            return True
    return False


def path_allowed(target: str | None, paths: dict[str, list[str]] | None) -> bool:
    """Replicates `code/aiosh-cli/src/pep.ts:pathAllowed()` in Python.
    Deny list wins over allow list."""
    if not paths:
        return True
    deny = paths.get("deny", []) or []
    for p in deny:
        if target is not None and (target == p or target.startswith(p + "/")
                                  or (p.endswith("/") and target.startswith(p))):
            return False
    allow = paths.get("allow", []) or []
    if not allow:
        # An empty allow list with a non-empty deny list means "deny-only";
        # any non-deny target is allowed.
        return True
    if target is None:
        return False
    for p in allow:
        if target == p or target.startswith(p + "/") \
                or (p.endswith("/") and target.startswith(p)):
            return True
    return False


def network_allowed(target: str | None, networks: Iterable[str] | None) -> bool:
    """Return whether a target host/IP is inside the grant's network
    scope. CIDR entries are checked with ipaddress; hostname entries
    are exact-match only. An absent/empty network scope is deny-by-
    default for a network target only when the caller explicitly
    supplied a networks policy; otherwise legacy path checks apply."""
    allowed = list(networks or [])
    if not allowed:
        return True
    if target is None:
        return False
    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        return target in allowed
    for item in allowed:
        try:
            if address in ipaddress.ip_network(item, strict=False):
                return True
        except ValueError:
            if target == item:
                return True
    return False


def grant_check(
    conn: sqlite3.Connection,
    grant_id: str | None,
    tool: str,
    target: str | None = None,
) -> dict[str, Any]:
    """Authoritative gate. Returns {"ok": True} or {"ok": False, "reason": str}.

    Rules (mirror `code/aiosh-cli/src/pep.ts:PepStore.check`):
      - read-only tool + no grant → allowed (caller took risk-aware path)
      - pentest.* / irreversible + no grant → refused with reason
      - grant present but not in scope → refused with reason
      - grant present but path outside allow/deny → refused
      - grant expired → refused
      - grant unknown or revoked → refused
    """
    irreversible = (
        tool.startswith("pentest.")
        or tool.startswith("fs.write")
        or tool in {"system.reboot", "system.shutdown"}
    )
    if grant_id is None:
        if irreversible:
            return {"ok": False,
                    "reason": f"irreversible tool '{tool}' requires explicit PEP grant"}
        return {"ok": True}
    g = load_grant(conn, grant_id)
    if g is None:
        return {"ok": False, "reason": f"unknown or revoked grant: {grant_id}"}
    # Expiry check (also covers revoked, since load_grant returns None).
    # Fail CLOSED: a malformed timestamp refuses the grant instead of
    # crashing the gate unaudited or silently treating it as unexpired.
    now = dt.datetime.now(dt.timezone.utc)
    try:
        expires = dt.datetime.fromisoformat(g["expires_at"].replace("Z", "+00:00"))
    except (ValueError, TypeError, AttributeError):
        return {"ok": False,
                "reason": f"grant {grant_id} expired or has malformed expires_at"}
    if expires < now:
        return {"ok": False, "reason": f"grant {grant_id} expired"}
    if g.get("single_use", True) and g.get("redeemed_at") is not None:
        return {"ok": False, "reason": f"grant {grant_id} already redeemed at {g['redeemed_at']}"}
    # Scope check: tool must be in grant.scope.tools (glob match).
    scope_tools = g["scope"].get("tools", []) or []
    if not tool_glob_match(tool, scope_tools):
        return {"ok": False,
                "reason": (f"tool '{tool}' not in grant scope.tools="
                           f"{json.dumps(scope_tools, sort_keys=True)}")}
    # Scope check: network targets use scope.networks; filesystem
    # targets use scope.paths (deny-wins). The old implementation
    # applied paths to every target, which incorrectly rejected a
    # correctly scoped pentest IP such as 10.0.0.5.
    scope = g["scope"]
    networks = scope.get("networks") or []
    is_network_target = tool.startswith("pentest.") or tool.startswith("network.")
    if target is not None and is_network_target and networks:
        if not network_allowed(target, networks):
            return {"ok": False,
                    "reason": f"target '{target}' blocked by grant scope.networks"}
    elif target is not None and not path_allowed(target, scope.get("paths")):
        return {"ok": False,
                "reason": f"target '{target}' blocked by grant scope.paths"}
    return {"ok": True}


def grant_redeem(
    conn: sqlite3.Connection,
    grant_id: str,
    actor: str = "agent",
    actor_id: str = "agent:mcp@aiosh-mcp",
    tool: str = "",
    command: str = "",
    args: dict[str, Any] | None = None,
    target: str | None = None,
) -> dict[str, Any]:
    grant_id = grant_id.strip() if grant_id else ""
    if not grant_id:
        return {"ok": False, "reason": "empty or whitespace grant_id"}

    try:
        conn.execute("PRAGMA busy_timeout = 5000;")
    except Exception:
        pass

    chk = grant_check(conn, grant_id, tool, target)
    if not chk["ok"]:
        return chk

    g = load_grant(conn, grant_id)
    if not g:
        return {"ok": False, "reason": f"unknown or revoked grant: {grant_id}"}

    MAX_PARAM_LEN = 8192
    if len(tool) > MAX_PARAM_LEN or len(command) > MAX_PARAM_LEN:
        return {"ok": False, "reason": "tool or command parameter exceeds maximum allowed length (8192)"}

    now_iso = utcnow_iso()
    is_single_use = g.get("single_use", True)

    if is_single_use:
        cur = conn.execute("""
            UPDATE pep_grants SET redeemed_at = ?
            WHERE grant_id = ? AND redeemed_at IS NULL AND revoked_at IS NULL
        """, (now_iso, grant_id))
        if cur.rowcount == 0:
            existing = conn.execute("SELECT redeemed_at, revoked_at FROM pep_grants WHERE grant_id = ?", (grant_id,)).fetchone()
            if existing and existing["redeemed_at"]:
                return {"ok": False, "reason": f"single-use grant {grant_id} already redeemed at {existing['redeemed_at']}"}
            return {"ok": False, "reason": f"grant {grant_id} already redeemed concurrently or revoked"}
    else:
        conn.execute("UPDATE pep_grants SET redeemed_at = ? WHERE grant_id = ?", (now_iso, grant_id))

    try:
        row = write_audit_row(conn, {
            "ts": now_iso,
            "actor": actor,
            "actor_id": actor_id,
            "tool": "pep.capability.redeem",
            "command": command or f"redeem {grant_id}",
            "args": args or {"grant_id": grant_id, "tool": tool, "command": command},
            "target": target,
            "outcome": "ok",
            "outcome_detail": None,
            "constitution_rev": g.get("constitution_rev", "v0.0"),
            "grant_token": grant_id,
            "c_flags": {"c1": False, "c2": False, "c3": False, "c4": False},
        })
        return {"ok": True, "grant_id": grant_id, "audit_row": row}
    except Exception as exc:
        if is_single_use:
            conn.execute("UPDATE pep_grants SET redeemed_at = NULL WHERE grant_id = ? AND redeemed_at = ?", (grant_id, now_iso))
        return {"ok": False, "reason": f"audit ring write failed during redemption: {exc}"}


def cFlagsFor(tool: str, target: str | None,
              args: dict[str, Any]) -> dict[str, bool]:
    """Replicates `code/aiosh-cli/src/constitution.ts:cFlagsFor()` in Python.
    Conservative: flag anything suspicious."""
    return {
        # C-1: Pillar-A scope (ethical hacking requires authorized grant).
        "c1": tool.startswith("pentest."),
        # C-2: user desktop / system sovereignty.
        "c2": tool.startswith("gui.") or tool in {"system.reboot", "system.shutdown"},
        # C-3: irreversible / non-idempotent effects.
        "c3": tool.startswith("fs.write")
              or tool in {"system.reboot", "system.shutdown"}
              or (tool.startswith("pentest.") and bool(args.get("persist"))),
        # C-4: audit ring is always written.
        "c4": True,
    }


def _insert_audit_row(
    conn: sqlite3.Connection,
    proto: dict[str, Any],
    prev_hash: str | None = None,
) -> AuditRow:
    """Insert one audit row without committing. If prev_hash is None,
    continue from the current chain head (live row, else latest segment
    checkpoint, else genesis)."""
    prev = prev_hash if prev_hash is not None else head_hash(conn)
    # Defensive: strip any "id" / "hash" fields before computing.
    safe_proto = {k: v for k, v in proto.items() if k not in {"id", "hash"}}
    safe_proto["prev_hash"] = prev
    h = sha256_hex(prev + canonical(safe_proto))
    cur = conn.execute(
        """INSERT INTO audit_ring
           (ts, actor, actor_id, tool, command, args_json, target,
            outcome, outcome_detail, constitution_rev, grant_token,
            c1, c2, c3, c4,
            policy_revision, classify_rule_ids_json, classify_evidence_json,
            classify_overall_verdict, classify_verdict_reason,
            prev_hash, hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                   ?, ?, ?, ?,
                   ?, ?, ?, ?, ?,
                   ?, ?)""",
        (
            safe_proto["ts"],
            safe_proto["actor"],
            safe_proto["actor_id"],
            safe_proto["tool"],
            safe_proto["command"],
            canonical(safe_proto["args"]),
            safe_proto.get("target"),
            safe_proto["outcome"],
            safe_proto.get("outcome_detail"),
            safe_proto.get("constitution_rev"),
            safe_proto.get("grant_token"),
            int(bool(safe_proto["c_flags"]["c1"])),
            int(bool(safe_proto["c_flags"]["c2"])),
            int(bool(safe_proto["c_flags"]["c3"])),
            int(bool(safe_proto["c_flags"]["c4"])),
            safe_proto.get("policy_revision"),
            (canonical(safe_proto["classify_rule_ids"])
             if safe_proto.get("classify_rule_ids") is not None else None),
            (canonical(safe_proto["classify_evidence"])
             if safe_proto.get("classify_evidence") is not None else None),
            safe_proto.get("classify_overall_verdict"),
            safe_proto.get("classify_verdict_reason"),
            safe_proto["prev_hash"],
            h,
        ),
    )
    return AuditRow(
        id=int(cur.lastrowid or 0),
        ts=safe_proto["ts"],
        actor=safe_proto["actor"],
        actor_id=safe_proto["actor_id"],
        tool=safe_proto["tool"],
        command=safe_proto["command"],
        args=safe_proto["args"],
        target=safe_proto.get("target"),
        outcome=safe_proto["outcome"],
        outcome_detail=safe_proto.get("outcome_detail"),
        constitution_rev=safe_proto.get("constitution_rev"),
        grant_token=safe_proto.get("grant_token"),
        c_flags=safe_proto["c_flags"],
        policy_revision=safe_proto.get("policy_revision"),
        classify_rule_ids=safe_proto.get("classify_rule_ids"),
        classify_evidence=safe_proto.get("classify_evidence"),
        classify_overall_verdict=safe_proto.get("classify_overall_verdict"),
        classify_verdict_reason=safe_proto.get("classify_verdict_reason"),
        prev_hash=safe_proto["prev_hash"],
        hash=h,
    )


def write_audit_row(
    conn: sqlite3.Connection,
    proto: dict[str, Any],
    prev_hash: str | None = None,
) -> AuditRow:
    """Append one row to the audit ring. Cross-substrate invariant with TS."""
    ensure_pep_schema(conn)  # no-op if CLI has already created the table.
    ensure_audit_schema(conn)  # Sprint 2 migration: add classifier columns.
    row = _insert_audit_row(conn, proto, prev_hash=prev_hash)
    conn.commit()
    return row


# Sprint 2 schema migration: ensure the classifier-decision columns exist.
# Mirrors the same `maybeAddColumn_` migration in code/aiosh-cli/src/audit.ts.
_CLASSIFIER_COLUMNS = (
    ("policy_revision", "TEXT"),
    ("classify_rule_ids_json", "TEXT"),
    ("classify_evidence_json", "TEXT"),
    ("classify_overall_verdict", "TEXT"),
    ("classify_verdict_reason", "TEXT"),
)


def ensure_audit_schema(conn: sqlite3.Connection) -> None:
    """Create the shared audit table and add Sprint-2 classifier columns.
    Idempotent. Old rows (NULL in these columns) keep their original
    hashes because verify() omits NULL classifier fields from the
    recomputed proto — see verify() in this module and the equivalent
    `maybeAddColumn_` / conditional-proto logic in audit.ts."""
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS audit_ring (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        actor TEXT NOT NULL,
        actor_id TEXT NOT NULL,
        tool TEXT NOT NULL,
        command TEXT NOT NULL,
        args_json TEXT NOT NULL,
        target TEXT,
        outcome TEXT NOT NULL,
        outcome_detail TEXT,
        constitution_rev TEXT,
        grant_token TEXT,
        c1 INTEGER NOT NULL DEFAULT 0,
        c2 INTEGER NOT NULL DEFAULT 0,
        c3 INTEGER NOT NULL DEFAULT 0,
        c4 INTEGER NOT NULL DEFAULT 0,
        prev_hash TEXT NOT NULL,
        hash TEXT NOT NULL UNIQUE
    );
    CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_ring(ts);
    CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_ring(actor);
    CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_ring(tool);
    """)
    cur = conn.execute("PRAGMA table_info(audit_ring)")
    existing = {row[1] for row in cur.fetchall()}
    for col, decl in _CLASSIFIER_COLUMNS:
        if col in existing:
            continue
        conn.execute(f"ALTER TABLE audit_ring ADD COLUMN {col} {decl}")
    conn.commit()
