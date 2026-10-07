"""Proof of Restraint — Restraint Proof Generator (Component 4).

Sprint / Architecture: ADR-0037, PLAN.md §Layer 2, Invariant I-4.
Generates self-contained cryptographic packages proving negative attestation (non-use)
of an authorized capability grant across a specified time window.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from . import anchors as anchors_mod
from . import audit_client as ac
from . import retention as retention_mod


@dataclass(frozen=True)
class RestraintProofPackage:
    schema_version: int
    proof_id: str
    generated_at: str
    grant: dict[str, Any]
    window: dict[str, str]
    anchors: dict[str, Any]
    segments_checked: list[dict[str, Any]]
    live_range: dict[str, Any]
    verdict: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "proof_id": self.proof_id,
            "generated_at": self.generated_at,
            "grant": self.grant,
            "window": self.window,
            "anchors": self.anchors,
            "segments_checked": self.segments_checked,
            "live_range": self.live_range,
            "verdict": self.verdict,
        }

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)


def _default_anchors_path() -> Path:
    base = os.environ.get("AIOSH_HOME", f"{os.environ.get('HOME', '/tmp')}/.aios")
    return Path(base) / "anchors" / "anchors.jsonl"


def _validate_iso_timestamp(ts: str, param_name: str) -> None:
    if not isinstance(ts, str) or not ts.strip():
        raise ValueError(f"PARAM_INVALID: {param_name} must be a non-empty ISO-8601 string")
    try:
        cleaned = ts.replace("Z", "+00:00")
        dt.datetime.fromisoformat(cleaned)
    except Exception as exc:
        raise ValueError(f"PARAM_INVALID: {param_name} ({ts}) is not a valid ISO-8601 timestamp: {exc}")


def _validate_safe_path(p: str | Path | None) -> Path:
    if p is None:
        return _default_anchors_path()
    s = str(p)
    if "\0" in s:
        raise ValueError("PARAM_INVALID: anchors_path contains NUL byte")
    return Path(s).resolve()


def generate_restraint_proof(
    conn: sqlite3.Connection,
    grant_id: str,
    window_start: str,
    window_end: str,
    anchors_path: Optional[str | Path] = None,
) -> RestraintProofPackage:
    """Generate self-contained RestraintProofPackage for grant_id across [window_start, window_end]."""
    _validate_iso_timestamp(window_start, "window_start")
    _validate_iso_timestamp(window_end, "window_end")

    if window_start > window_end:
        raise ValueError(f"WINDOW_INVALID: window_start ({window_start}) > window_end ({window_end})")

    # 1. Validate grant existence and unredeemed status
    grant = ac.load_grant(conn, grant_id)
    if grant is None:
        raise ValueError(f"GRANT_NOT_FOUND: grant {grant_id} not found in pep_grants")

    if grant.get("redeemed_at") is not None:
        raise ValueError(f"GRANT_REDEEMED: grant {grant_id} was redeemed at {grant['redeemed_at']}")

    # Check audit ring directly for any redemption row
    cur = conn.execute(
        "SELECT id, ts, command FROM audit_ring WHERE grant_token = ? AND tool = 'pep.capability.redeem'",
        (grant_id,),
    )
    redeem_row = cur.fetchone()
    if redeem_row:
        raise ValueError(f"GRANT_REDEEMED: grant {grant_id} recorded redeemed at row {redeem_row[0]}")

    # 2. Find covering anchors
    p = _validate_safe_path(anchors_path)
    loaded_anchors = anchors_mod.load_anchors(p)
    if not loaded_anchors:
        raise ValueError(f"NO_COVERING_ANCHORS: no anchors found in {p}")

    sorted_anchors = sorted(loaded_anchors, key=lambda a: (a.seq, a.timestamp))

    # Eligible start anchor: latest anchor with timestamp <= window_start
    start_candidates = [a for a in sorted_anchors if a.timestamp <= window_start]
    if not start_candidates:
        raise ValueError(f"NO_COVERING_ANCHORS: no anchor precedes window_start ({window_start})")
    start_anchor = start_candidates[-1]

    # Eligible end anchor: earliest anchor with timestamp >= window_end
    end_candidates = [a for a in sorted_anchors if a.timestamp >= window_end]
    if not end_candidates:
        raise ValueError(f"NO_COVERING_ANCHORS: no anchor succeeds window_end ({window_end})")
    end_anchor = end_candidates[0]

    if start_anchor.seq > end_anchor.seq:
        raise ValueError(f"NO_COVERING_ANCHORS: start anchor seq {start_anchor.seq} > end anchor seq {end_anchor.seq}")

    # 3. Check archived segments via Bloom filter
    segments_checked: list[dict[str, Any]] = []
    if ac._segments_table_exists(conn):
        cur = conn.execute(
            """SELECT segment_id, first_row_id, last_row_id, archive_sha256,
                      bloom_m_bits, bloom_k, bloom_hex
               FROM audit_segments
               WHERE last_row_id >= ? AND first_row_id <= ?
               ORDER BY segment_id ASC""",
            (start_anchor.seq, end_anchor.seq),
        )
        for row in cur.fetchall():
            m = row["bloom_m_bits"]
            k = row["bloom_k"]
            bits = bytearray.fromhex(row["bloom_hex"])
            in_bloom = retention_mod.bloom_test(bits, m, k, grant_id)
            if in_bloom:
                raise ValueError(f"GRANT_REDEEMED: segment {row['segment_id']} bloom indicates grant present")
            segments_checked.append({
                "segment_id": row["segment_id"],
                "row_range": [row["first_row_id"], row["last_row_id"]],
                "archive_sha256": row["archive_sha256"],
                "bloom_negative": True,
            })

    # 4. Check live range in audit_ring
    cur = conn.execute(
        "SELECT id, hash, grant_token, tool FROM audit_ring WHERE id >= ? AND id <= ? ORDER BY id ASC",
        (start_anchor.seq, end_anchor.seq),
    )
    live_rows = cur.fetchall()
    chain_hashes: list[str] = []
    for r in live_rows:
        chain_hashes.append(r["hash"])
        if r["grant_token"] == grant_id and r["tool"] == "pep.capability.redeem":
            raise ValueError(f"GRANT_REDEEMED: live audit row {r['id']} redeemed grant {grant_id}")

    first_seq = live_rows[0]["id"] if live_rows else start_anchor.seq
    last_seq = live_rows[-1]["id"] if live_rows else end_anchor.seq

    now_iso = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    proof_seed = f"{grant_id}:{window_start}:{window_end}:{now_iso}"
    proof_id = f"por_{hashlib.sha256(proof_seed.encode('utf-8')).hexdigest()[:24]}"

    return RestraintProofPackage(
        schema_version=1,
        proof_id=proof_id,
        generated_at=now_iso,
        grant=grant,
        window={"start": window_start, "end": window_end},
        anchors={
            "start_anchor": start_anchor.to_dict(),
            "end_anchor": end_anchor.to_dict(),
        },
        segments_checked=segments_checked,
        live_range={
            "first_seq": first_seq,
            "last_seq": last_seq,
            "row_count": len(live_rows),
            "hashes": chain_hashes,
        },
        verdict="PROVABLY_RESTRAINED",
    )
