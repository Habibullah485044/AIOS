"""Tool Registry & Taxonomy operator CLI (T-03385 scaffold / T-03386 impl).

Spec: docs/tasks/evidence/T-03384-spec.md. Read-only inspection of the trusted tool catalog:
``list``, ``get``, ``decide``, ``export``, ``check`` (TOOLCLI-INV1..TOOLCLI-INV4).

    aiosh-tool-registry get aios_pentest_nmap --json
    python -m aiosh_mcp.tool_registry_cli check aios.fs.read pentest.nmap
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import tempfile
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from aiosh_mcp.tool_registry_data_model import Category, ToolRegistryError, _shown, default_catalog

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2

TOOLCLI_ERR_USAGE = "TOOLCLI_ERR_USAGE"
TOOLCLI_ERR_IO = "TOOLCLI_ERR_IO"
TOOLCLI_ERR_UNAVAILABLE = "TOOLCLI_ERR_UNAVAILABLE"

SUBCOMMANDS = ("list", "get", "decide", "export", "check")
MAX_NAMES = 256
MAX_NAME_CHARS = 256
MAX_SHOWN_CHARS = 80


@dataclass
class CliResult:
    """Standard CLI result (spec §1): exit code plus the --json payload."""

    exit_code: int
    subcommand: str
    data: Optional[Dict[str, Any]] = None
    error_code: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"ok": self.exit_code == EXIT_SUCCESS, "subcommand": self.subcommand, "data": self.data,
                "error_code": self.error_code, "error": self.error}


class _UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    """argparse that raises instead of printing and exiting (TOOLCLI-INV2)."""

    def error(self, message: str) -> None:  # type: ignore[override]
        raise _UsageError(message)


def _build_parser() -> _Parser:
    parser = _Parser(prog="aiosh-tool-registry", add_help=False)
    sub = parser.add_subparsers(dest="subcommand", parser_class=_Parser)
    ls = sub.add_parser("list", add_help=False)
    ls.add_argument("--category", choices=[c.value for c in Category])
    ls.add_argument("--json", action="store_true")
    gt = sub.add_parser("get", add_help=False)
    gt.add_argument("name")
    gt.add_argument("--json", action="store_true")
    dc = sub.add_parser("decide", add_help=False)
    dc.add_argument("name")
    dc.add_argument("--target")
    dc.add_argument("--require-grant", action="store_true")
    dc.add_argument("--mode", choices=["shadow", "strict"], default="shadow")
    dc.add_argument("--json", action="store_true")
    ex = sub.add_parser("export", add_help=False)
    ex.add_argument("--out")
    ex.add_argument("--json", action="store_true")
    ck = sub.add_parser("check", add_help=False)
    ck.add_argument("names", nargs="+")
    ck.add_argument("--json", action="store_true")
    return parser


def _usage(sub: str, message: str) -> CliResult:
    return CliResult(EXIT_USAGE, sub, error_code=TOOLCLI_ERR_USAGE, error=f"{TOOLCLI_ERR_USAGE}: {message}")


def _decision_dict(d: Any) -> Dict[str, Any]:
    return {"canonical": d.canonical, "registered": d.registered, "requires_grant": d.requires_grant,
            "irreversible": d.irreversible, "scope_kinds": [k.value for k in d.scope_kinds],
            "disagreements": list(d.disagreements), "mode": d.mode}


def _export_to(path: str, text: str) -> Dict[str, Any]:
    """Atomic write (TOOLCLI-INV4): temp file in the target directory, then rename into place."""
    target = os.path.abspath(path)
    if os.path.lexists(target):
        st = os.lstat(target)
        if not stat.S_ISREG(st.st_mode):           # directory, symlink, device, FIFO ...
            raise OSError(f"refusing to overwrite a non-regular file: {_shown(path)}")
    parent = os.path.dirname(target) or "."
    data = text.encode("utf-8")
    fd, tmp = tempfile.mkstemp(prefix=".tool-registry-", suffix=".tmp", dir=parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return {"path": target, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def dispatch_cli(argv: List[str]) -> CliResult:
    """Pure CLI core: argv in, CliResult out (spec §1). Never raises (TOOLCLI-INV2)."""
    argv = [a if isinstance(a, str) else str(a) for a in (argv or [])]
    sub = argv[0] if argv and argv[0] in SUBCOMMANDS else "unknown"
    try:
        if any("\0" in a for a in argv):
            raise _UsageError("argument contains a NUL byte")
        ns = _build_parser().parse_args(argv)
        if ns.subcommand is None:
            raise _UsageError(f"expected a subcommand: {' | '.join(SUBCOMMANDS)}")
        names = ns.names if ns.subcommand == "check" else ([ns.name] if hasattr(ns, "name") else [])
        if len(names) > MAX_NAMES:
            raise _UsageError(f"at most {MAX_NAMES} names")
        if any(len(n) > MAX_NAME_CHARS for n in names):
            raise _UsageError(f"names are at most {MAX_NAME_CHARS} characters")
    except _UsageError as exc:
        return _usage(sub, str(exc))
    try:
        catalog = default_catalog()
    except ToolRegistryError as exc:
        return CliResult(EXIT_FAILURE, sub, error_code=TOOLCLI_ERR_UNAVAILABLE,
                         error=f"{TOOLCLI_ERR_UNAVAILABLE}: tool catalog unavailable ({exc.code})")
    if ns.subcommand == "list":
        entries = [e.to_dict() for e in catalog.entries() if ns.category is None or e.category.value == ns.category]
        return CliResult(EXIT_SUCCESS, "list", data={"count": len(entries), "entries": entries})
    if ns.subcommand == "get":
        entry = catalog.resolve(ns.name)
        data = {"registered": entry is not None, "entry": (entry or catalog.profile(ns.name)).to_dict()}
        if entry is None:
            return CliResult(EXIT_FAILURE, "get", data=data, error=f"not registered: {_shown(ns.name)}")
        return CliResult(EXIT_SUCCESS, "get", data=data)
    if ns.subcommand == "decide":
        from aiosh_mcp.tool_registry_service import ToolRegistryService
        decision = ToolRegistryService(catalog, mode=ns.mode).decide(ns.name, ns.target, require_grant=ns.require_grant)
        return CliResult(EXIT_SUCCESS, "decide", data=_decision_dict(decision))
    if ns.subcommand == "export":
        text = catalog.export_json()
        if not ns.out:
            return CliResult(EXIT_SUCCESS, "export", data={"export": text})
        try:
            return CliResult(EXIT_SUCCESS, "export", data=_export_to(ns.out, text))
        except OSError as exc:
            return CliResult(EXIT_FAILURE, "export", error_code=TOOLCLI_ERR_IO,
                             error=f"{TOOLCLI_ERR_IO}: {_shown(exc.strerror or exc)}")
    # check
    rows = []
    for name in ns.names:
        entry = catalog.resolve(name)
        prof = entry or catalog.profile(name)
        rows.append({"name": _shown(name), "registered": entry is not None, "canonical": prof.canonical,
                     "requires_grant": prof.requires_grant, "irreversible": prof.irreversible})
    missing = sum(1 for r in rows if not r["registered"])
    return CliResult(EXIT_FAILURE if missing else EXIT_SUCCESS, "check",
                     data={"names": rows, "unregistered": missing},
                     error=f"{missing} name(s) not registered" if missing else None)


def _human(result: CliResult) -> List[str]:
    if result.error_code:
        return [result.error or result.error_code]
    d = result.data or {}
    if result.subcommand == "list":
        return [f"{e['canonical']:<36} {e['category']:<14} {e['effect']:<11} "
                f"{'irreversible' if e['irreversible'] else '-':<12} {e['scope_kind']}" for e in d["entries"]] + \
               [f"{d['count']} tool(s)"]
    if result.subcommand == "get":
        e = d["entry"]
        head = "registered" if d["registered"] else "NOT REGISTERED (fail-closed profile)"
        return [f"{e['canonical']}: {head}"] + [f"  {k}: {v}" for k, v in e.items() if k != "canonical"]
    if result.subcommand == "decide":
        return [f"  {k}: {v}" for k, v in d.items()]
    if result.subcommand == "check":
        return [f"{'ok  ' if r['registered'] else 'MISSING'} {r['name']} -> {r['canonical']}"
                f"{'  (grant)' if r['requires_grant'] else ''}" for r in d["names"]]
    if result.subcommand == "export":
        return [f"wrote {d['bytes']} bytes to {_shown(d['path'])} (sha256 {d['sha256']})"]
    return []


def main(argv: Optional[List[str]] = None) -> int:
    """Console entry point; returns the process exit code."""
    args = list(sys.argv[1:] if argv is None else argv)
    result = dispatch_cli(args)
    try:
        if result.subcommand == "export" and result.data and "export" in result.data and "--json" not in args:
            print(result.data["export"])                    # exactly the export, for piping
        elif "--json" in args:
            print(json.dumps(result.to_dict(), ensure_ascii=True, sort_keys=True))
        else:
            stream = sys.stdout if result.exit_code != EXIT_USAGE else sys.stderr
            for line in _human(result):
                print(line, file=stream)
        sys.stdout.flush()
    except BrokenPipeError:                                 # `| head`: exit quietly (TOOLCLI-INV3)
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except (OSError, ValueError):
            pass
        return EXIT_SUCCESS
    return result.exit_code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
