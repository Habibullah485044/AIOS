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


def generate_keypair() -> tuple[str, str]:
    """Generate (private_key_hex, public_key_hex) using Ed25519."""
    raise NotImplementedError("T-02854 scaffold: generate_keypair not implemented yet")


def sign_checkpoint(
    seq: int,
    head_hash: str,
    timestamp: str,
    private_key_hex: str,
) -> AnchorRecord:
    """Sign (seq, head_hash, timestamp) and produce an AnchorRecord."""
    raise NotImplementedError("T-02854 scaffold: sign_checkpoint not implemented yet")


def verify_checkpoint(anchor: AnchorRecord) -> bool:
    """Cryptographically verify an AnchorRecord against its embedded pubkey."""
    raise NotImplementedError("T-02854 scaffold: verify_checkpoint not implemented yet")


def append_anchor(anchor: AnchorRecord, anchors_path: str | Path) -> None:
    """Append an anchor record to external JSONL file."""
    raise NotImplementedError("T-02854 scaffold: append_anchor not implemented yet")


def load_anchors(anchors_path: str | Path) -> list[AnchorRecord]:
    """Load all anchor records from external JSONL file."""
    raise NotImplementedError("T-02854 scaffold: load_anchors not implemented yet")


def verify_chain_against_anchors(
    chain_rows: list[dict[str, Any]],
    anchors: list[AnchorRecord],
    trusted_pubkey: Optional[str] = None,
) -> tuple[bool, Optional[str]]:
    """Verify chain completeness and hash integrity against signed checkpoints."""
    raise NotImplementedError("T-02854 scaffold: verify_chain_against_anchors not implemented yet")
