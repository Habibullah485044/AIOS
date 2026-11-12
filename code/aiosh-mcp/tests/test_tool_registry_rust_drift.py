"""Cross-substrate drift: the catalog's `irreversible` vs Rust `pep::is_irreversible` (T-03418; spec T-03414 §1).

The Rust binary is not built on every host, so the rule is parsed from `aiosh-core/src/pep.rs` itself. Known
differences are listed explicitly in both directions; any *new* difference fails, so drift can never grow
silently. Fixing a listed difference means removing it from the list.
"""

import re
from pathlib import Path

import pytest

from aiosh_mcp.tool_registry_data_model import default_catalog

#: Located from this test file (always inside the repo), not from the installed package (T-03419: a relocated or
#: wheel-installed package used to turn the check into a skip).
PEP_RS = Path(__file__).resolve().parents[2] / "aiosh-rust" / "aiosh-core" / "src" / "pep.rs"

#: Rust says reversible, the catalog says irreversible (Rust weaker; research T-03363 B4.4).
RUST_WEAKER = {"pentest.tshark"}
#: Rust says irreversible, the catalog does not. Empty since T-03419 (backup/release made irreversible).
CATALOG_WEAKER: set = set()
#: Every token the parser models; anything else left in the body fails the test (T-03419 finding D).
_UNDERSTOOD = re.compile(r'tool\s*==\s*"[^"]*"|tool\.starts_with\("[^"]*"\)|\|\||return\s+false\s*;|\bif\b|[{}()\s]')


def rust_rule():
    body = PEP_RS.read_text(encoding="utf-8").split("pub fn is_irreversible(tool: &str) -> bool {", 1)[1]
    body = body.split("\n}\n", 1)[0]
    code = "\n".join(line.split("//", 1)[0] for line in body.splitlines())
    leftover = _UNDERSTOOD.sub("", code)
    assert leftover == "", f"pep.rs is_irreversible uses a construct the drift parser does not model: {leftover[:80]!r}"
    early, rest = code.split("return false;", 1)
    not_exact = set(re.findall(r'tool == "([^"]+)"', early))
    not_prefix = tuple(re.findall(r'tool\.starts_with\("([^"]+)"\)', early))
    exact = set(re.findall(r'tool == "([^"]+)"', rest))
    prefix = tuple(re.findall(r'tool\.starts_with\("([^"]+)"\)', rest))

    def is_irreversible(tool: str) -> bool:
        if tool in not_exact or tool.startswith(not_prefix):
            return False
        return tool in exact or tool.startswith(prefix)
    return is_irreversible, (not_exact, not_prefix, exact, prefix)


def test_parser_sees_the_rule():
    _, (not_exact, not_prefix, exact, prefix) = rust_rule()
    assert "pentest.tshark" in not_exact and "network." in not_prefix
    assert "system.reboot" in exact and "pentest." in prefix and "fs.write" in prefix


def test_rust_drift_is_exactly_the_known_list():
    rust, _ = rust_rule()
    rust_weaker, catalog_weaker = set(), set()
    for e in default_catalog().entries():
        r = rust(e.canonical)
        if e.irreversible and not r:
            rust_weaker.add(e.canonical)
        elif r and not e.irreversible:
            catalog_weaker.add(e.canonical)
    print(f"rust weaker: {sorted(rust_weaker)}; catalog weaker: {sorted(catalog_weaker)}")
    assert rust_weaker == RUST_WEAKER, "Rust is_irreversible drift changed; update RUST_WEAKER or fix the Rust rule"
    assert catalog_weaker == CATALOG_WEAKER, "catalog vs Rust drift changed; update CATALOG_WEAKER or fix the catalog"
