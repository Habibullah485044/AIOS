"""AI Control Plane Model Backend Adapters Documentation Subsystem (T-03245 scaffold).

Provides reference topic definitions, topic catalog, keyword search, and schema discovery in compliance with SPEC-MODEL-BACKEND-ADAPTERS-DOCUMENTATION and PoR Invariant I-2.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

MAX_DOC_QUERY_LEN = 128
MAX_DOC_SEARCH_RESULTS = 10
MAX_TOPICS_LIMIT = 256

MODDOC_ERR_NOT_FOUND = "MODDOC_ERR_NOT_FOUND"
MODDOC_ERR_INVALID_ID = "MODDOC_ERR_INVALID_ID"
MODDOC_ERR_QUERY_BOUNDS = "MODDOC_ERR_QUERY_BOUNDS"

BIDI_AND_INVISIBLE_CODEPOINTS = {
    0x200B, 0x200C, 0x200D, 0x200E, 0x200F,
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
    0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x2066, 0x2067, 0x2068, 0x2069,
    0xFEFF,
}

TOPIC_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\.]{1,64}$")


def sanitize_doc_query(s: str) -> str:
    """Strips control codes, invisible unicode codepoints, normalizes NFKC, and clamps query length."""
    if not s:
        return ""
    normalized = unicodedata.normalize("NFKC", str(s))
    filtered = []
    for c in normalized:
        cp = ord(c)
        if cp < 32 or (127 <= cp <= 159) or cp in BIDI_AND_INVISIBLE_CODEPOINTS:
            continue
        filtered.append(c)
    cleaned = "".join(filtered).strip()
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned[:MAX_DOC_QUERY_LEN]


def validate_topic_id(topic_id: str) -> None:
    """Validates topic ID against traversal tokens, NUL bytes, and syntax bounds (MODDOC-INV3)."""
    trimmed = unicodedata.normalize("NFKC", (topic_id or "").strip())
    if not trimmed:
        raise ValueError(f"{MODDOC_ERR_INVALID_ID}: empty topic ID")
    if "\0" in trimmed or ".." in trimmed or "/" in trimmed or "\\" in trimmed:
        raise ValueError(f"{MODDOC_ERR_INVALID_ID}: forbidden path or traversal character in topic ID")
    if not TOPIC_ID_PATTERN.match(trimmed):
        raise ValueError(f"{MODDOC_ERR_INVALID_ID}: topic ID does not match valid syntax")


@dataclass(frozen=True)
class ModelAdapterDocTopic:
    topic_id: str
    title: str
    category: str
    summary: str
    body: str
    tags: List[str] = field(default_factory=list)
    updated_at: str = "2026-10-29"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "topic_id": self.topic_id,
            "title": self.title,
            "category": self.category,
            "summary": self.summary,
            "body": self.body,
            "tags": list(self.tags),
            "updated_at": self.updated_at,
        }


class ModelAdapterDocCatalog:
    """In-memory documentation catalog and search engine for model backend adapters."""

    def __init__(self) -> None:
        self._topics: Dict[str, ModelAdapterDocTopic] = {}

    def get_topic(self, topic_id: str) -> Optional[ModelAdapterDocTopic]:
        raise NotImplementedError("Scaffold only — implemented in T-03246")

    def list_topics(self) -> List[ModelAdapterDocTopic]:
        raise NotImplementedError("Scaffold only — implemented in T-03246")

    def search(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        raise NotImplementedError("Scaffold only — implemented in T-03246")
