#!/usr/bin/env python3
"""Compliance Mapping / Configuration — focused unit tests (T-02907).

Contract: docs/tasks/evidence/T-02904-spec.md
Research: docs/tasks/evidence/T-02903-configuration-research.md

Covers valid input, invalid input, boundary values and the primary failure
mode of the configuration resolver. Asserts *observable* behaviour only —
returned values, source attribution, and the files that do (or do not) get
touched — never internal call structure.

Style: no pytest dependency (pytest still collects every test_* function),
matching code/aiosh-mcp/tests/test_compliance_unit.py.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aiosh_mcp import compliance, compliance_config as cc  # noqa: E402

PASS = "[PASS]"
FAIL = "[FAIL]"


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

@contextmanager
def clean_env():
    """Isolate both config env vars, restoring whatever was there."""
    keys = (cc.ENV_COMPLIANCE_MAP_PATH, cc.ENV_COMPLIANCE_CONFIG)
    saved = {k: os.environ.get(k) for k in keys}
    for k in keys:
        os.environ.pop(k, None)
    try:
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


@contextmanager
def temp_dir(prefix="compliance-config-"):
    with tempfile.TemporaryDirectory(prefix=prefix) as td:
        yield Path(td)


def write_json(path: Path, obj) -> Path:
    path.write_text(json.dumps(obj), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Valid input
# ---------------------------------------------------------------------------

def test_defaults_match_spec_section_3_1():
    """Happy path: a fresh resolution with nothing set yields spec §3.1
    defaults and attributes every key to `default`."""
    with clean_env():
        r = cc.resolve()
    cfg = r["config"]
    assert cfg["version"] == "1.0.0"
    assert cfg["store_path"] == "docs/compliance_map.json"
    assert cfg["max_store_file_bytes"] == 1024 * 1024
    assert cfg["max_entries"] == 1024
    assert cfg["audit_all_queries"] is False
    assert cfg["audit_all_mutations"] is True
    assert set(r["source"]) == set(cfg), (r["source"], cfg)
    assert all(v == "default" for v in r["source"].values()), r["source"]


def test_valid_config_file_supplies_values_with_file_source():
    """Happy path: a well-formed config file is read and attributed."""
    with clean_env(), temp_dir() as td:
        cfg_path = write_json(td / "compliance_config.json", {
            "store_path": str(td / "store.json"),
            "max_entries": 42,
            "max_store_file_bytes": 65536,
            "audit_all_queries": True,
        })
        r = cc.resolve(arg_config=str(cfg_path))
    cfg = r["config"]
    assert cfg["store_path"] == str(td / "store.json")
    assert cfg["max_entries"] == 42
    assert cfg["max_store_file_bytes"] == 65536
    assert cfg["audit_all_queries"] is True
    assert r["source"]["store_path"] == "file"
    assert r["source"]["max_entries"] == "file"
    assert r["source"]["version"] == "default"


def test_unknown_config_keys_are_ignored_not_persisted():
    """Foreign keys in a config file must not leak into the resolved
    config (the schema is closed, spec §3.1)."""
    with clean_env(), temp_dir() as td:
        cfg_path = write_json(td / "compliance_config.json", {
            "store_path": str(td / "s.json"),
            "totally_unknown_key": "evil",
        })
        r = cc.resolve(arg_config=str(cfg_path))
    assert "totally_unknown_key" not in r["config"]
    assert "totally_unknown_key" not in r["source"]


# ---------------------------------------------------------------------------
# Precedence ladder (spec §3.2)
# ---------------------------------------------------------------------------

def test_precedence_argument_beats_env_beats_file_beats_default():
    """The full ladder, one level at a time, asserted by observable
    source attribution."""
    with clean_env(), temp_dir() as td:
        cfg_path = write_json(td / "compliance_config.json",
                              {"store_path": str(td / "from_file.json")})
        env_store = str(td / "from_env.json")
        arg_store = str(td / "from_arg.json")

        # level 4
        r = cc.resolve()
        assert r["config"]["store_path"] == "docs/compliance_map.json"
        assert r["source"]["store_path"] == "default"

        # level 3
        os.environ[cc.ENV_COMPLIANCE_CONFIG] = str(cfg_path)
        r = cc.resolve()
        assert r["config"]["store_path"] == str(td / "from_file.json")
        assert r["source"]["store_path"] == "file"

        # level 2
        os.environ[cc.ENV_COMPLIANCE_MAP_PATH] = env_store
        r = cc.resolve()
        assert r["config"]["store_path"] == env_store
        assert r["source"]["store_path"] == "env"

        # level 1
        r = cc.resolve(arg_path=arg_store)
        assert r["config"]["store_path"] == arg_store
        assert r["source"]["store_path"] == "argument"

        # level 1 moves store_path ONLY — unrelated keys keep their origin.
        assert r["config"]["max_entries"] == 1024      # untouched by that file
        assert r["source"]["max_entries"] == "default"


def test_load_config_env_var_selects_file():
    """`AIOSH_COMPLIANCE_CONFIG` selects the config file when no explicit
    argument is given (level 3 via environment)."""
    with clean_env(), temp_dir() as td:
        cfg_path = write_json(td / "compliance_config.json",
                              {"max_entries": 7})
        os.environ[cc.ENV_COMPLIANCE_CONFIG] = str(cfg_path)
        r = cc.resolve()
    assert r["config"]["max_entries"] == 7
    assert r["source"]["max_entries"] == "file"


# ---------------------------------------------------------------------------
# Invalid input — the primary failure modes (spec §4.2)
# ---------------------------------------------------------------------------

def test_env_path_hygiene_rejects_traversal_and_control_chars():
    """CWE-15 (spec §4.3): a bad env value is REJECTED and reported, never
    applied — the default store stays authoritative."""
    bad_values = [
        "../evil.json",
        "docs/../../etc/x.json",
        "docs/\x01x.json",
        "",
        "   ",
        "a" * (cc.MAX_CONFIG_PATH_LEN + 1),
    ]
    with clean_env():
        for bad in bad_values:
            os.environ[cc.ENV_COMPLIANCE_MAP_PATH] = bad
            r = cc.resolve()
            assert r["config"]["store_path"] == "docs/compliance_map.json", (bad, r)
            assert r["source"]["store_path"] == "env_invalid", (bad, r)


def test_hygiene_ok_is_total_and_matches_predicate():
    """The predicate returns a bool for any input and never raises."""
    cases = {
        "docs/compliance_map.json": True,
        "/tmp/abs/store.json": True,
        "": False,
        "  ": False,
        "../x.json": False,
        "a/../b.json": False,
        "docs/\x00x.json": False,
        "docs/\x7fx.json": False,
        "a" * (cc.MAX_CONFIG_PATH_LEN + 1): False,
        "a" * cc.MAX_CONFIG_PATH_LEN: True,
    }
    for value, expected in cases.items():
        got = cc.hygiene_ok(value)
        assert got is expected, (repr(value), got, expected)
    # Totality: non-string inputs must not raise.
    for weird in (None, 7, ["x"], {"a": 1}):
        assert isinstance(cc.hygiene_ok(weird), bool), weird


def test_malformed_config_fails_closed_with_parse_code():
    """PRIMARY FAILURE MODE: malformed JSON raises COMPLIANCECONF_ERR_PARSE
    and never returns a partial/defaulted config silently."""
    with clean_env(), temp_dir() as td:
        bad = td / "bad.json"
        bad.write_text("{not valid json", encoding="utf-8")
        try:
            cc.load_config(str(bad))
        except Exception as e:
            assert cc.COMPLIANCECONF_ERR_PARSE in str(e), str(e)
        else:
            raise AssertionError("malformed config must fail closed")


def test_non_object_config_root_fails_closed():
    """A JSON array/scalar root is structurally valid JSON but not a
    config — must still fail closed."""
    with clean_env(), temp_dir() as td:
        for payload in ("[1,2,3]", '"just a string"', "42", "null"):
            p = td / "root.json"
            p.write_text(payload, encoding="utf-8")
            try:
                cc.load_config(str(p))
            except Exception as e:
                assert cc.COMPLIANCECONF_ERR_PARSE in str(e), (payload, str(e))
            else:
                raise AssertionError(f"root {payload!r} must fail closed")


def test_malformed_config_does_not_let_reads_proceed_silently():
    """End-to-end failure mode: with a broken config selected, resolution
    surfaces the error instead of quietly using some other store."""
    with clean_env(), temp_dir() as td:
        bad = td / "bad.json"
        bad.write_text("{broken", encoding="utf-8")
        os.environ[cc.ENV_COMPLIANCE_CONFIG] = str(bad)
        try:
            cc.resolve()
        except Exception as e:
            assert cc.COMPLIANCECONF_ERR_PARSE in str(e), str(e)
        else:
            raise AssertionError("resolve must not swallow a broken config")


def test_missing_config_file_is_not_an_error():
    """Spec §4.2 last row: an absent config file yields defaults."""
    with clean_env(), temp_dir() as td:
        r = cc.load_config(str(td / "absent.json"))
    assert r == cc.default_config()


def test_empty_or_missing_fields_fall_back_to_defaults():
    """Partial / empty config objects are padded with defaults rather than
    raising (inert-field policy, spec §4.2)."""
    assert cc.validate({}) == cc.default_config()
    assert cc.validate(None) == cc.default_config()
    partial = cc.validate({"max_entries": 5})
    assert partial["max_entries"] == 5
    assert partial["store_path"] == "docs/compliance_map.json"
    assert partial["version"] == "1.0.0"


def test_non_object_config_argument_rejected():
    """A non-dict config argument is a caller error, not a silent no-op."""
    for bad in ("a string", 42, ["list"], None if False else 3.14):
        try:
            cc.validate(bad)
        except Exception as e:
            assert cc.COMPLIANCECONF_ERR_VALIDATION in str(e), (bad, str(e))
        else:
            if bad is None:
                continue  # documented as "treat as empty"
            raise AssertionError(f"non-object {bad!r} must be rejected")


# ---------------------------------------------------------------------------
# Boundary values (spec §3.1 / §5)
# ---------------------------------------------------------------------------

def test_max_entries_boundaries_clamp():
    lo, hi, default = cc.MIN_MAX_ENTRIES, cc.MAX_MAX_ENTRIES, cc.DEFAULT_MAX_ENTRIES
    assert cc.validate({"max_entries": lo})["max_entries"] == lo
    assert cc.validate({"max_entries": hi})["max_entries"] == hi
    assert cc.validate({"max_entries": lo - 1})["max_entries"] == lo
    assert cc.validate({"max_entries": hi + 1})["max_entries"] == hi
    assert cc.validate({"max_entries": 999999999})["max_entries"] == hi
    assert cc.validate({"max_entries": -1})["max_entries"] == lo


def test_max_store_file_bytes_boundaries_clamp():
    lo, hi = cc.MIN_MAX_STORE_FILE_BYTES, cc.MAX_MAX_STORE_FILE_BYTES
    assert lo == 4096 and hi == 16 * 1024 * 1024
    assert cc.validate({"max_store_file_bytes": lo})["max_store_file_bytes"] == lo
    assert cc.validate({"max_store_file_bytes": hi})["max_store_file_bytes"] == hi
    assert cc.validate({"max_store_file_bytes": lo - 1})["max_store_file_bytes"] == lo
    assert cc.validate({"max_store_file_bytes": hi + 1})["max_store_file_bytes"] == hi


def test_config_file_size_boundary_exact_cap_accepted():
    """Exactly 64 KiB is accepted; 64 KiB + 1 is rejected before parsing."""
    with clean_env(), temp_dir() as td:
        base = b'{"store_path":"docs/compliance_map.json"}'
        exact = td / "exact.json"
        exact.write_bytes(base + b" " * (cc.MAX_CONFIG_FILE_BYTES - len(base)))
        assert exact.stat().st_size == cc.MAX_CONFIG_FILE_BYTES
        loaded = cc.load_config(str(exact))
        assert loaded["store_path"] == "docs/compliance_map.json"

        over = td / "over.json"
        over.write_bytes(b" " * (cc.MAX_CONFIG_FILE_BYTES + 1))
        try:
            cc.load_config(str(over))
        except Exception as e:
            assert cc.COMPLIANCECONF_ERR_FILE_SIZE in str(e), str(e)
        else:
            raise AssertionError("cap+1 must be rejected before parsing")


def test_env_path_length_boundary():
    """Exactly MAX_CONFIG_PATH_LEN passes; one more fails."""
    at_limit = "a" * cc.MAX_CONFIG_PATH_LEN
    assert cc.hygiene_ok(at_limit) is True
    assert cc.hygiene_ok("a" * (cc.MAX_CONFIG_PATH_LEN + 1)) is False


# ---------------------------------------------------------------------------
# Security-relevant invariants (spec §5)
# ---------------------------------------------------------------------------

def test_audit_all_mutations_cannot_be_disabled():
    """Spec §5.4: config can never switch mutation auditing off."""
    assert cc.validate({"audit_all_mutations": False})["audit_all_mutations"] is True
    assert cc.validate({"audit_all_mutations": 0})["audit_all_mutations"] is True
    assert cc.validate({"audit_all_mutations": None})["audit_all_mutations"] is True
    # ...including when it arrives through a config file.
    with clean_env(), temp_dir() as td:
        cfg_path = write_json(td / "c.json", {"audit_all_mutations": False})
        r = cc.resolve(arg_config=str(cfg_path))
    assert r["config"]["audit_all_mutations"] is True


def test_bad_explicit_argument_reaches_validate_path_not_silently_defaulted():
    """REGRESSION GUARD (T-02906 §7.1): an explicit operator path is
    passed through unchanged so the real path validator can refuse it.
    Substituting the default would turn a refusal into a success."""
    with clean_env():
        r = cc.resolve(arg_path="../evil.json")
    assert r["config"]["store_path"] == "../evil.json"
    assert r["source"]["store_path"] == "argument"
    try:
        compliance.validate_path(r["config"]["store_path"])
    except Exception as e:
        assert compliance.COMPLIANCESVC_ERR_PATH_TRAVERSAL in str(e), str(e)
    else:
        raise AssertionError("bad explicit path must be refused downstream")


def test_resolution_creates_no_files():
    """Reads are pure: resolving must not create the config file, the
    store, or any side-effect artifact."""
    with clean_env(), temp_dir() as td:
        before = set(td.iterdir())
        cc.resolve(arg_config=str(td / "nope.json"))
        cc.resolve()
        cc.load_config(str(td / "nope.json"))
        after = set(td.iterdir())
    assert before == after, after - before


def test_store_path_resolver_agrees_with_load_store_default():
    """Observable cross-check: the resolver's default is the same path the
    store loader uses, so config cannot silently redirect reads."""
    with clean_env():
        resolved = cc.resolve()["config"]["store_path"]
    assert resolved == compliance.DEFAULT_STORE_PATH
    assert resolved == "docs/compliance_map.json"


# ---------------------------------------------------------------------------
# Standalone runner (pytest collects the same functions)
# ---------------------------------------------------------------------------

def test_config_directory_path_fails_closed():
    """A directory path provided as config file must fail closed with COMPLIANCECONF_ERR_IO."""
    with clean_env(), temp_dir() as td:
        dir_path = td / "subfolder"
        dir_path.mkdir()
        try:
            cc.load_config(str(dir_path))
        except Exception as e:
            assert cc.COMPLIANCECONF_ERR_IO in str(e), str(e)
        else:
            raise AssertionError("directory path must fail closed")


def test_config_non_utf8_fails_closed():
    """Non-UTF-8 bytes in config file must fail closed with COMPLIANCECONF_ERR_PARSE."""
    with clean_env(), temp_dir() as td:
        bad_utf8 = td / "bad_utf8.json"
        bad_utf8.write_bytes(b"\xff\xfe\x00\x00")
        try:
            cc.load_config(str(bad_utf8))
        except Exception as e:
            assert cc.COMPLIANCECONF_ERR_PARSE in str(e), str(e)
        else:
            raise AssertionError("non-UTF-8 config must fail closed")


def main() -> int:
    tests = [(name, fn) for name, fn in list(globals().items())
             if name.startswith("test_") and callable(fn)]
    failed = []
    for name, fn in tests:
        try:
            fn()
            print(f"{PASS} {name}")
        except Exception as exc:  # noqa: BLE001 — report every failure
            failed.append(name)
            print(f"{FAIL} {name}: {type(exc).__name__}: {exc}")
    print("-" * 60)
    if failed:
        print(f"{len(failed)}/{len(tests)} FAILED: {', '.join(failed)}")
        return 1
    print(f"ALL {len(tests)} T-02907 CONFIG UNIT TESTS PASSED!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
