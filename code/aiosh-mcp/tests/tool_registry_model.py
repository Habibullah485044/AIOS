"""Spec-derived oracles and generators for the tool registry property tests (T-03415 scaffold).

Spec: docs/tasks/evidence/T-03414-spec.md. Every oracle is written from the operator doc
(docs/SPEC-TOOL-REGISTRY-DATA-MODEL.md §2, §6e) and the task specs, never by calling the code under test
(AUTOTEST-INV2). Generators are driven by ``random.Random(seed)`` so a failure replays from its seed (AUTOTEST-INV1).
"""

from __future__ import annotations

import os
import random
from typing import Any, Dict, List, Optional, Tuple


def seeds() -> List[int]:
    """Seeds from ``AIOSH_TOOLREG_FUZZ_SEEDS`` (comma list, default 1,2,3)."""
    raw = os.environ.get("AIOSH_TOOLREG_FUZZ_SEEDS", "1,2,3")
    return [int(s) for s in raw.split(",") if s.strip()]


def n_cases() -> int:
    """Cases per property from ``AIOSH_TOOLREG_FUZZ_N`` (default 300)."""
    return int(os.environ.get("AIOSH_TOOLREG_FUZZ_N", "300"))


def gen_kwargs(rng: random.Random) -> Dict[str, Any]:
    raise NotImplementedError("T-03416: gen_kwargs")


def entry_should_be_valid(kw: Dict[str, Any]) -> bool:
    raise NotImplementedError("T-03416: entry_should_be_valid")


def gen_name_set(rng: random.Random) -> List[Tuple[str, Tuple[str, ...]]]:
    raise NotImplementedError("T-03416: gen_name_set")


def catalog_should_collide(entries: List[Tuple[str, Tuple[str, ...]]]) -> bool:
    raise NotImplementedError("T-03416: catalog_should_collide")


def legacy_floor(name: Any) -> Tuple[bool, bool]:
    raise NotImplementedError("T-03416: legacy_floor")


def caution(a: Any) -> Tuple[bool, Optional[bool], Optional[bool], bool]:
    raise NotImplementedError("T-03416: caution")


def gen_config_sources(rng: random.Random) -> Dict[str, Any]:
    raise NotImplementedError("T-03416: gen_config_sources")


def expected_config(src: Dict[str, Any]) -> Dict[str, Any]:
    raise NotImplementedError("T-03416: expected_config")
