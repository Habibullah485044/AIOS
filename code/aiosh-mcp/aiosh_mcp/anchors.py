"""Proof of Restraint — Chain Anchoring & Completeness Checkpoints (Component 3).

Sprint / Architecture: ADR-0037, PLAN.md §Layer 2, Invariant I-3.
Provides Ed25519-signed checkpoints anchoring chain heads (seq, head_hash, timestamp)
outside the SQLite audit.db so an adversary cannot rewrite or truncate the audit log.
Hardened against input tampering, key confusion, path injection, and corrupted storage (T-02859).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

MAX_ANCHORS_FILE_SIZE = 10 * 1024 * 1024  # 10 MB file cap for anchors.jsonl
_HEX_64_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


def _validate_hex_key(key_hex: str, name: str = "key") -> bytes:
    if not isinstance(key_hex, str) or not _HEX_64_PATTERN.match(key_hex.strip()):
        raise ValueError(f"Invalid {name}: must be a 64-character hex string (32 bytes)")
    try:
        return bytes.fromhex(key_hex.strip())
    except ValueError as exc:
        raise ValueError(f"Invalid {name}: bad hex encoding ({exc})") from exc


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
        if not isinstance(data, dict):
            raise ValueError(f"AnchorRecord data must be a dict, got {type(data).__name__}")
        for req in ("seq", "head_hash", "timestamp", "pubkey", "signature"):
            if req not in data:
                raise ValueError(f"AnchorRecord missing required field: '{req}'")

        return cls(
            schema_version=int(data.get("schema_version", 1)),
            seq=int(data["seq"]),
            head_hash=str(data["head_hash"]).strip(),
            timestamp=str(data["timestamp"]).strip(),
            pubkey=str(data["pubkey"]).strip(),
            signature=str(data["signature"]).strip(),
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
    priv_bytes = _validate_hex_key(private_key_hex, name="private_key")
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
        pub_bytes = _validate_hex_key(anchor.pubkey, name="pubkey")
        pub = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        if len(anchor.signature) != 128:
            return False
        sig_bytes = bytes.fromhex(anchor.signature)
        payload_bytes = _canonical_payload(anchor.seq, anchor.head_hash, anchor.timestamp)
        pub.verify(sig_bytes, payload_bytes)
        return True
    except Exception:
        return False


def append_anchor(anchor: AnchorRecord, anchors_path: str | Path) -> None:
    """Append an anchor record to external JSONL file with safe directory creation."""
    p = Path(anchors_path).resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt" and hasattr(os, "chmod"):
        try:
            os.chmod(p.parent, 0o700)
        except OSError:
            pass

    line = anchor.to_canonical_json() + "\n"
    with open(p, "a", encoding="utf-8") as f:
        f.write(line)
        f.flush()

    if os.name != "nt" and hasattr(os, "chmod"):
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass


def load_anchors(anchors_path: str | Path) -> list[AnchorRecord]:
    """Load all anchor records from external JSONL file, enforcing bounded size and valid schemas."""
    p = Path(anchors_path).resolve()
    if not p.is_file():
        return []

    size = p.stat().st_size
    if size > MAX_ANCHORS_FILE_SIZE:
        raise ValueError(f"Anchors file {p} exceeds size cap of {MAX_ANCHORS_FILE_SIZE} bytes ({size} bytes)")

    records = []
    with open(p, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            trimmed = line.strip()
            if not trimmed:
                continue
            try:
                data = json.loads(trimmed)
                records.append(AnchorRecord.from_dict(data))
            except Exception as exc:
                raise ValueError(f"Corrupted anchor record at line {line_num} in {p}: {exc}") from exc
    return records


def verify_chain_against_anchors(
    chain_rows: list[dict[str, Any]],
    anchors: list[AnchorRecord],
    trusted_pubkey: Optional[str] = None,
) -> tuple[bool, Optional[str]]:
    """Verify chain completeness and hash integrity against signed checkpoints."""
    if not anchors:
        return True, None

    if trusted_pubkey:
        try:
            _validate_hex_key(trusted_pubkey, name="trusted_pubkey")
        except ValueError as exc:
            return False, f"INVALID_TRUSTED_PUBKEY: {exc}"

    row_map = {int(r["id"]): r.get("hash") for r in chain_rows if "id" in r}
    max_chain_id = max(row_map.keys()) if row_map else 0

    for anchor in anchors:
        if trusted_pubkey and anchor.pubkey.lower() != trusted_pubkey.lower():
            return False, f"UNTRUSTED_KEY: anchor pubkey {anchor.pubkey} != trusted {trusted_pubkey}"

        if not verify_checkpoint(anchor):
            return False, f"SIGNATURE_INVALID: anchor at seq {anchor.seq} failed signature verification"

        if anchor.seq > max_chain_id:
            return False, f"TRUNCATION_DETECTED: anchor requires seq {anchor.seq} but chain ends at {max_chain_id}"

        chain_hash = row_map.get(anchor.seq)
        if chain_hash is None or chain_hash != anchor.head_hash:
            return False, f"FORK_DETECTED: chain row at seq {anchor.seq} has hash {chain_hash} != anchor head_hash {anchor.head_hash}"

    return True, None
