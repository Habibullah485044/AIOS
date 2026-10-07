"""Proof of Restraint — Chain Anchoring & Completeness Checkpoints (Component 3).

Sprint / Architecture: ADR-0037, PLAN.md §Layer 2, Invariant I-3.
Provides Ed25519-signed checkpoints anchoring chain heads (seq, head_hash, timestamp)
outside the SQLite audit.db so an adversary cannot rewrite or truncate the audit log.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


@dataclass(frozen=True)
class AnchorRecord:
    schema_version: int
    seq: int
    head_hash: str
    timestamp: str
    pubkey: str
    signature: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "seq": self.seq,
            "head_hash": self.head_hash,
            "timestamp": self.timestamp,
            "pubkey": self.pubkey,
            "signature": self.signature,
        }

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AnchorRecord:
        return cls(
            schema_version=int(data.get("schema_version", 1)),
            seq=int(data["seq"]),
            head_hash=str(data["head_hash"]),
            timestamp=str(data["timestamp"]),
            pubkey=str(data["pubkey"]),
            signature=str(data["signature"]),
        )


def _canonical_payload(seq: int, head_hash: str, timestamp: str) -> bytes:
    payload = {
        "head_hash": head_hash,
        "seq": int(seq),
        "timestamp": timestamp,
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def generate_keypair() -> tuple[str, str]:
    """Generate (private_key_hex, public_key_hex) using Ed25519."""
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    raw_priv = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    raw_pub = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw_priv.hex(), raw_pub.hex()


def sign_checkpoint(
    seq: int,
    head_hash: str,
    timestamp: str,
    private_key_hex: str,
) -> AnchorRecord:
    """Sign (seq, head_hash, timestamp) and produce an AnchorRecord."""
    priv_bytes = bytes.fromhex(private_key_hex)
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    pub = priv.public_key()
    pub_hex = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()

    payload_bytes = _canonical_payload(seq, head_hash, timestamp)
    sig = priv.sign(payload_bytes)

    return AnchorRecord(
        schema_version=1,
        seq=int(seq),
        head_hash=head_hash,
        timestamp=timestamp,
        pubkey=pub_hex,
        signature=sig.hex(),
    )


def verify_checkpoint(anchor: AnchorRecord) -> bool:
    """Cryptographically verify an AnchorRecord against its embedded pubkey."""
    try:
        pub_bytes = bytes.fromhex(anchor.pubkey)
        pub = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        sig_bytes = bytes.fromhex(anchor.signature)
        payload_bytes = _canonical_payload(anchor.seq, anchor.head_hash, anchor.timestamp)
        pub.verify(sig_bytes, payload_bytes)
        return True
    except Exception:
        return False


def append_anchor(anchor: AnchorRecord, anchors_path: str | Path) -> None:
    """Append an anchor record to external JSONL file."""
    p = Path(anchors_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    line = anchor.to_canonical_json() + "\n"
    with open(p, "a", encoding="utf-8") as f:
        f.write(line)


def load_anchors(anchors_path: str | Path) -> list[AnchorRecord]:
    """Load all anchor records from external JSONL file."""
    p = Path(anchors_path)
    if not p.is_file():
        return []
    records = []
    with open(p, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            records.append(AnchorRecord.from_dict(json.loads(line)))
    return records


def verify_chain_against_anchors(
    chain_rows: list[dict[str, Any]],
    anchors: list[AnchorRecord],
    trusted_pubkey: Optional[str] = None,
) -> tuple[bool, Optional[str]]:
    """Verify chain completeness and hash integrity against signed checkpoints."""
    if not anchors:
        return True, None

    row_map = {int(r["id"]): r.get("hash") for r in chain_rows if "id" in r}
    max_chain_id = max(row_map.keys()) if row_map else 0

    for anchor in anchors:
        if trusted_pubkey and anchor.pubkey != trusted_pubkey:
            return False, f"UNTRUSTED_KEY: anchor pubkey {anchor.pubkey} != trusted {trusted_pubkey}"

        if not verify_checkpoint(anchor):
            return False, f"SIGNATURE_INVALID: anchor at seq {anchor.seq} failed signature verification"

        if anchor.seq > max_chain_id:
            return False, f"TRUNCATION_DETECTED: anchor requires seq {anchor.seq} but chain ends at {max_chain_id}"

        chain_hash = row_map.get(anchor.seq)
        if chain_hash is None or chain_hash != anchor.head_hash:
            return False, f"FORK_DETECTED: chain row at seq {anchor.seq} has hash {chain_hash} != anchor head_hash {anchor.head_hash}"

    return True, None
