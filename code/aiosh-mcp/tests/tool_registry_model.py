"""Spec-derived oracles and generators for the tool registry property tests (T-03415 scaffold / T-03416 impl).

Spec: docs/tasks/evidence/T-03414-spec.md. Every oracle here is written from the operator doc
(docs/SPEC-TOOL-REGISTRY-DATA-MODEL.md §2, §6e) and the task specs, never by calling the code under test
(AUTOTEST-INV2). Generators are driven by ``random.Random(seed)`` so a failure replays from its seed (AUTOTEST-INV1).
"""

from __future__ import annotations

import json
import os
import random
import re
import unicodedata
from typing import Any, Dict, List, Optional, Tuple

# ---- environment knobs (spec §3) ---------------------------------------------------------------------------------

def seeds() -> List[int]:
    raw = os.environ.get("AIOSH_TOOLREG_FUZZ_SEEDS", "1,2,3")
    return [int(s) for s in raw.split(",") if s.strip()]


def n_cases() -> int:
    return int(os.environ.get("AIOSH_TOOLREG_FUZZ_N", "300"))


# ---- doc §2: the taxonomy ----------------------------------------------------------------------------------------

CATEGORIES = ("fs.read", "fs.write", "process", "audit", "pentest", "network", "gui", "system", "agent_loop",
              "model_backend", "mcp_core", "service", "admin")
EFFECTS = ("read_only", "additive", "destructive")
SCOPES = ("none", "path", "network")
CANONICAL = re.compile(r"^[a-z][a-z0-9_-]*(\.[a-z0-9_-]+)*$")
MCP_NAME = re.compile(r"^[A-Za-z0-9_.\-]+$")
MAX_NAME, MAX_TITLE, MAX_ALIASES = 64, 64, 8
#: Rule 7 (doc §2): names today's enforcement treats as irreversible, case-insensitive.
IRREVERSIBLE_PREFIXES = ("pentest.", "fs.write", "process.", "shell.")
IRREVERSIBLE_EXACT = ("system.reboot", "system.shutdown", "pentest")
#: grant_check's own (case-sensitive) grant set (T-03374 §2 / T-03376 legacy rules).
GRANT_PREFIXES = ("pentest.", "fs.write")
GRANT_EXACT = ("system.reboot", "system.shutdown")


def irreversible_by_name(name: str) -> bool:
    n = name.casefold()
    return n.startswith(IRREVERSIBLE_PREFIXES) or n in IRREVERSIBLE_EXACT


def entry_should_be_valid(kw: Dict[str, Any]) -> bool:
    """Doc §2 name rules + consistency rules 1-7, and the title/alias bounds of doc §5."""
    c = kw["canonical"]
    if type(c) is not str or not (1 <= len(c) <= MAX_NAME) or not CANONICAL.fullmatch(c):
        return False
    aliases = kw["mcp_names"]
    if type(aliases) is not tuple or len(aliases) > MAX_ALIASES:
        return False
    if any(type(a) is not str or not (1 <= len(a) <= MAX_NAME) or not MCP_NAME.fullmatch(a) for a in aliases):
        return False
    t = kw["title"]
    if type(t) is not str or not (1 <= len(t) <= MAX_TITLE) or not t.isprintable():
        return False
    if any(type(kw[k]) is not bool for k in ("irreversible", "open_world", "requires_grant", "idempotent")):
        return False
    if kw["category"] not in CATEGORIES or kw["effect"] not in EFFECTS or kw["scope_kind"] not in SCOPES:
        return False
    ro, irrev = kw["effect"] == "read_only", kw["irreversible"]
    rules = [
        not (ro and (irrev or kw["idempotent"])),                                          # 1
        not irrev or (kw["requires_grant"] and not ro),                                    # 2
        kw["scope_kind"] != "network" or kw["open_world"],                                 # 3
        kw["category"] != "pentest" or (irrev and kw["scope_kind"] != "none"),             # 4
        kw["category"] not in ("fs.write", "system") or irrev,                             # 5
        kw["category"] != "network" or kw["scope_kind"] == "network",                      # 6
        not irreversible_by_name(c) or (irrev and kw["requires_grant"]),                   # 7
    ]
    return all(rules)


_NAME_PARTS = ("aios", "fs", "read", "write", "x", "tool", "net", "a1", "b-c", "d_e")
_RISKY = ("pentest.", "fs.write", "process.", "shell.", "system.reboot", "system.shutdown", "network.", "pentest",
          "system.", "PENTEST.", "Fs.Write")


def gen_canonical(rng: random.Random) -> Any:
    roll = rng.random()
    if roll < 0.55:
        name = ".".join(rng.choice(_NAME_PARTS) for _ in range(rng.randint(1, 3)))
        if rng.random() < 0.4:
            prefix = rng.choice(_RISKY)
            name = prefix + (name if prefix.endswith(".") else "")
        return name
    return rng.choice(["", "x" * 64, "x" * 65, "1abc", "a..b", "a.", ".a", "A.b", "a b", "a/b", "ä.b", "a\x00",
                       "pentest", "system.reboot", None, 7])


def gen_kwargs(rng: random.Random) -> Dict[str, Any]:
    aliases: Any = tuple(rng.choice(["a_b", "A.B-c", "x" * 64, "x" * 65, "", "a b", "a/b", "ok"])
                         for _ in range(rng.randint(0, 9)))
    if rng.random() < 0.03:
        aliases = list(aliases)
    return {
        "canonical": gen_canonical(rng),
        "mcp_names": aliases,
        "title": rng.choice(["Title", "t" * 64, "t" * 65, "", "a\x1bb", "a‮b", "a b", "a\x9bb", "ok ü", 5]),
        "category": rng.choice(CATEGORIES),
        "effect": rng.choice(EFFECTS),
        "irreversible": rng.choice([True, False, True, False, 1]),
        "scope_kind": rng.choice(SCOPES),
        "open_world": rng.choice([True, False]),
        "requires_grant": rng.choice([True, False]),
        "idempotent": rng.choice([True, False]),
    }


# ---- doc §2 "Names": the collision fold ------------------------------------------------------------------------------

def fold(name: str) -> str:
    return re.sub(r"[._\-]+", ".", unicodedata.normalize("NFKC", name).casefold())


def catalog_should_collide(entries: List[Tuple[str, Tuple[str, ...]]]) -> bool:
    """True iff two names share a fold, unless one is the *own canonical* of the other's entry (doc §2)."""
    seen: Dict[str, Tuple[int, bool]] = {}
    for idx, (canonical, aliases) in enumerate(entries):
        for pos, name in enumerate((canonical, *aliases)):
            key = fold(name)
            if key in seen:
                prev_idx, prev_is_canonical = seen[key]
                if not (prev_idx == idx and (prev_is_canonical or pos == 0)):
                    return True
            else:
                seen[key] = (idx, pos == 0)
    return False


def gen_name_set(rng: random.Random) -> List[Tuple[str, Tuple[str, ...]]]:
    stems = ["aios.t.alpha", "aios.t.beta", "aios.t.gamma"]
    out = []
    for _ in range(rng.randint(1, 4)):
        stem = rng.choice(stems)
        canonical = stem if rng.random() < 0.7 else stem.replace(".", rng.choice(["_", "-", "."]))
        variants = [stem.replace(".", "_"), stem.replace(".", "-"), stem.upper().replace(".", "_"), stem + "_x",
                    "other_" + stem.replace(".", "_")]
        aliases = tuple(rng.choice(variants) for _ in range(rng.randint(0, 2)))
        out.append((canonical, aliases))
    return out


# ---- P3: the never-weaker floor --------------------------------------------------------------------------------------

def legacy_floor(name: Any) -> Tuple[bool, bool]:
    """(requires_grant, irreversible) that today's enforcement already applies to ``name``."""
    text = name if type(name) is str else ""
    grant = text.startswith(GRANT_PREFIXES) or text in GRANT_EXACT
    return grant, irreversible_by_name(text)


def gen_query_name(rng: random.Random, registered: List[str]) -> Any:
    base = rng.choice(registered)
    roll = rng.random()
    if roll < 0.2:
        return base
    if roll < 0.35:
        return base.upper()
    if roll < 0.5:
        return base.replace(".", rng.choice(["_", "-", ". "]))
    if roll < 0.6:
        return unicodedata.normalize("NFKC", base).translate({ord(c): ord(c) + 0xFEE0 for c in "abcdefghij"})
    if roll < 0.75:
        return rng.choice(_RISKY) + rng.choice(["x", "nmap", "", "a.b"])
    return rng.choice([None, 5, b"x", "", " ", "\x00", "a" * 300, "‮pentest.x", "pentest", "Pentest.Nmap"])


# ---- P4: annotation caution ------------------------------------------------------------------------------------------

def caution(a: Any) -> Tuple[bool, Optional[bool], Optional[bool], bool]:
    """(readOnly, destructive, idempotent, openWorld) as a client sees it, MCP defaults filled in."""
    if a is None:
        return (False, True, False, True)
    ro = a.readOnlyHint is True
    return (ro,
            None if ro else (True if a.destructiveHint is None else bool(a.destructiveHint)),
            None if ro else bool(a.idempotentHint),
            True if a.openWorldHint is None else bool(a.openWorldHint))


def contrary_claim(existing: Any) -> bool:
    """An existing annotation that says, or implies, the tool is not read-only (T-03396/T-03399 F2)."""
    return existing is not None and (existing.readOnlyHint is False or
                                     (existing.readOnlyHint is None and
                                      (existing.destructiveHint is True or existing.idempotentHint is False)))


def gen_annotation(rng: random.Random) -> Any:
    from mcp.types import ToolAnnotations
    if rng.random() < 0.2:
        return None
    pick = lambda: rng.choice([None, True, False])  # noqa: E731
    return ToolAnnotations(readOnlyHint=pick(), destructiveHint=pick(), idempotentHint=pick(), openWorldHint=pick())


# ---- P5: configuration (doc §6e) ------------------------------------------------------------------------------------

FIELDS = {"report_max_lines": (32, 1, 1000), "unregistered_samples": (50, 0, 200)}
LOCKED = ("catalog", "entries", "read_only_hint_categories", "grant_params", "path_params", "irreversible_names",
          "irreversible_prefixes")
ENV_NUM = {"report_max_lines": "AIOSH_TOOL_REGISTRY_REPORT_MAX_LINES",
           "unregistered_samples": "AIOSH_TOOL_REGISTRY_UNREGISTERED_SAMPLES"}


def mode_vote(raw: Any) -> Optional[str]:
    """``None`` = no opinion; otherwise the mode this source asks for (unrecognised = strict)."""
    if raw is None:
        return None
    if not isinstance(raw, str):
        return "strict"
    v = unicodedata.normalize("NFKC", raw).strip().lower()
    if not v:
        return None
    return v if v in ("shadow", "strict") else "strict"


def file_values(raw: bytes) -> Optional[Dict[str, Any]]:
    """The file's settings, or ``None`` when the file must be ignored (doc §6e rules)."""
    if len(raw) > 64 * 1024:
        return None
    try:
        text = raw.decode("utf-8-sig")
        pairs_seen: List[str] = []

        def hook(pairs):
            for k, _ in pairs:
                if k in pairs_seen:
                    raise ValueError("dup")
                pairs_seen.append(k)
            return dict(pairs)
        doc = json.loads(text, object_pairs_hook=hook)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    if not isinstance(doc, dict):
        return None
    for k, v in doc.items():
        if k in LOCKED or (k != "mode" and k not in FIELDS):
            return None
        if k == "mode" and not isinstance(v, str):
            return None
        if k in FIELDS and (isinstance(v, bool) or not isinstance(v, int)):
            return None
    return doc


def gen_config_sources(rng: random.Random) -> Dict[str, Any]:
    modes = [None, "shadow", "strict", "STRICT ", "ｓｈａｄｏｗ", "", "   ", "strct", "off"]
    file_doc = rng.choice([
        None, {"mode": "strict"}, {"mode": "shadow"}, {"report_max_lines": 5}, {"unregistered_samples": 500},
        {"report_max_lines": 0, "mode": "shadow"}, {"catalog": []}, {"nope": 1}, {"mode": 1},
        {"report_max_lines": True}, {"report_max_lines": "7"}, "dup", "bom", "utf16", "notjson", "array", "big",
    ])
    if isinstance(file_doc, dict):
        raw = json.dumps(file_doc).encode()
    else:
        raw = {None: None, "dup": b'{"mode": "strict", "mode": "shadow"}',
               "bom": json.dumps({"mode": rng.choice(["strict", "shadow"]), "report_max_lines": 9}).encode("utf-8-sig"),
               "utf16": '{"mode": "shadow"}'.encode("utf-16"), "notjson": b"{nope", "array": b"[1]",
               "big": b" " * (64 * 1024 + 1)}[file_doc]
    env_nums = {k: rng.choice([None, "", "7", " 12 ", "5000", "-1", "x", "3.5"]) for k in FIELDS}
    return {"arg_mode": rng.choice(modes), "env_mode": rng.choice(modes), "file": raw,
            "path_kind": rng.choice(["env", "env", "default", "missing", "bad", "none"]), "env_nums": env_nums}


def expected_config(src: Dict[str, Any]) -> Dict[str, Any]:
    """Doc §6e: numbers argument → env → file → default then clamp; mode strictest-wins; unusable config = strict."""
    kind = src["path_kind"]
    untrusted = False
    values: Dict[str, Any] = {}
    if kind in ("missing", "bad"):
        untrusted = True
    elif kind in ("env", "default") and src["file"] is not None:
        parsed = file_values(src["file"])
        if parsed is None:
            untrusted = True
        else:
            values = parsed
    elif kind == "env" and src["file"] is None:
        untrusted = True                                    # env names a file that does not exist
    out: Dict[str, Any] = {}
    for key, (default, lo, hi) in FIELDS.items():
        value = values.get(key, default)
        env = src["env_nums"][key]
        if env is not None and env.strip():
            try:
                value = int(env.strip())
            except ValueError:
                pass
        out[key] = min(hi, max(lo, value))
    votes = [mode_vote(src["arg_mode"]), mode_vote(src["env_mode"]), mode_vote(values.get("mode"))]
    out["mode"] = "strict" if untrusted or "strict" in votes else "shadow"
    return out
