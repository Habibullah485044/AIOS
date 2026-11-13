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
EXIT_INTERRUPTED = 130   # 128 + SIGINT, as the agent-loop CLI

TOOLCLI_ERR_USAGE = "TOOLCLI_ERR_USAGE"
TOOLCLI_ERR_IO = "TOOLCLI_ERR_IO"
TOOLCLI_ERR_UNAVAILABLE = "TOOLCLI_ERR_UNAVAILABLE"
TOOLCLI_ERR_INTERRUPTED = "TOOLCLI_ERR_INTERRUPTED"

SUBCOMMANDS = ("list", "get", "decide", "export", "check")
MAX_NAMES = 256
MAX_NAME_CHARS = 256
MAX_SHOWN_CHARS = 80
MAX_SHOWN_PATH_CHARS = 260
#: Defensive cap on an export (the largest possible catalog is < 1 MiB, T-03370).
MAX_EXPORT_BYTES = 4 * 1024 * 1024

USAGE = """usage: aiosh-tool-registry <command> [options]   (read-only view of the trusted tool catalog)

  list [--category C] [--json]                    every registered tool, optionally one category
  get <name> [--json]                             one tool by canonical or MCP name (exit 1 if unregistered)
  decide <name> [--require-grant] [--mode shadow|strict] [--json]
                                                  the registry service's decision for a call to <name>
  export [--out FILE] [--json]                    the catalog as canonical JSON (atomic write with --out)
  check <name>... [--json]                        exit 0 if every name is registered, 1 otherwise

exit codes: 0 ok, 1 negative result or I/O error, 2 usage, 130 interrupted"""


def _safe(text: Any) -> str:
    """Terminal-safe text for human output: printable ASCII kept, everything else escaped (T-03389 #2, #3, #5).

    Escaping (rather than dropping) keeps names distinguishable, and an ASCII result can be written to any
    stream encoding (a redirected Windows stdout is cp1252).
    """
    out = []
    for ch in str(text):
        code = ord(ch)
        out.append(ch if 0x20 <= code < 0x7F else ch.encode("unicode_escape").decode("ascii"))
    return "".join(out)


@dataclass
class CliResult:
    """Standard CLI result (spec §1): exit code plus the --json payload."""

    exit_code: int
    subcommand: str
    data: Optional[Dict[str, Any]] = None
    error_code: Optional[str] = None
    error: Optional[str] = None
    #: --json as argparse understood it (abbreviations included), not a raw argv match (T-03389 #7).
    as_json: bool = False

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


def _usage(sub: str, message: str, as_json: bool = False) -> CliResult:
    # argparse echoes raw argv ("unrecognized arguments: ..."): escape it before it can reach a terminal (#3)
    return CliResult(EXIT_USAGE, sub, error_code=TOOLCLI_ERR_USAGE,
                     error=f"{TOOLCLI_ERR_USAGE}: {_safe(message)[:400]}", as_json=as_json)


def _decision_dict(d: Any) -> Dict[str, Any]:
    return {"canonical": d.canonical, "registered": d.registered, "requires_grant": d.requires_grant,
            "irreversible": d.irreversible, "scope_kinds": [k.value for k in d.scope_kinds],
            "disagreements": list(d.disagreements), "mode": d.mode}


def _export_to(path: str, text: str) -> Dict[str, Any]:
    """Atomic write (TOOLCLI-INV4): temp file in the target directory, then rename into place."""
    target = os.path.abspath(path)
    mode = None
    if os.path.lexists(target):
        st = os.lstat(target)
        if not stat.S_ISREG(st.st_mode):           # directory, symlink, device, FIFO ...
            raise OSError(f"refusing to overwrite a non-regular file: {_safe(path)[:MAX_SHOWN_PATH_CHARS]}")
        mode = stat.S_IMODE(st.st_mode)
    parent = os.path.dirname(target) or "."
    data = text.encode("utf-8")
    if len(data) > MAX_EXPORT_BYTES:
        raise OSError(f"export is {len(data)} bytes; refusing more than {MAX_EXPORT_BYTES}")
    tmp = None
    try:
        # mkstemp inside the try: an interrupt right after it still removes the temp file (#10)
        fd, tmp = tempfile.mkstemp(prefix=".tool-registry-", suffix=".tmp", dir=parent)
        try:
            fh = os.fdopen(fd, "wb")
        except BaseException:
            os.close(fd)                           # Windows cannot delete a file that is still open
            raise
        with fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        if mode is not None:
            os.chmod(tmp, mode)                    # keep the replaced file's POSIX mode (#9; Windows ACLs: documented)
        os.replace(tmp, target)
    except BaseException:
        if tmp is not None:
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
    head = argv[: argv.index("--")] if "--" in argv else argv
    if "-h" in head or "--help" in head:
        return CliResult(EXIT_SUCCESS, sub if sub != "unknown" else "help", data={"usage": USAGE})
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
        return _usage(sub, str(exc), as_json="--json" in argv[: argv.index("--")] if "--" in argv else "--json" in argv)
    as_json = bool(getattr(ns, "json", False))
    if ns.subcommand == "export" and ns.out is not None and not ns.out.strip():
        return _usage("export", "--out needs a file path (empty value)", as_json)        # #6
    try:
        catalog = default_catalog()
    except ToolRegistryError as exc:
        return CliResult(EXIT_FAILURE, sub, error_code=TOOLCLI_ERR_UNAVAILABLE,
                         error=f"{TOOLCLI_ERR_UNAVAILABLE}: tool catalog unavailable ({exc.code})", as_json=as_json)
    if ns.subcommand == "list":
        entries = [e.to_dict() for e in catalog.entries() if ns.category is None or e.category.value == ns.category]
        return CliResult(EXIT_SUCCESS, "list", data={"count": len(entries), "entries": entries}, as_json=as_json)
    if ns.subcommand == "get":
        entry = catalog.resolve(ns.name)
        data = {"registered": entry is not None, "entry": (entry or catalog.profile(ns.name)).to_dict()}
        if entry is None:
            return CliResult(EXIT_FAILURE, "get", data=data, error=f"not registered: {_safe(_shown(ns.name))}", as_json=as_json)
        return CliResult(EXIT_SUCCESS, "get", data=data, as_json=as_json)
    if ns.subcommand == "decide":
        from aiosh_mcp.tool_registry_service import ToolRegistryService
        from aiosh_mcp.tool_registry_policy import preview
        svc = ToolRegistryService(catalog, mode=ns.mode)
        decision = svc.decide(ns.name, ns.target, require_grant=ns.require_grant)
        data = _decision_dict(decision)
        data["target_checked"] = False      # the decision is per tool name; targets are checked by the PEP (#11)
        data["policy"] = preview(svc, decision, require_grant=ns.require_grant)        # T-03428
        return CliResult(EXIT_SUCCESS, "decide", data=data, as_json=as_json)
    if ns.subcommand == "export":
        text = catalog.export_json()
        if not ns.out:
            return CliResult(EXIT_SUCCESS, "export", data={"export": text}, as_json=as_json)
        try:
            return CliResult(EXIT_SUCCESS, "export", data=_export_to(ns.out, text), as_json=as_json)
        except OSError as exc:
            return CliResult(EXIT_FAILURE, "export", error_code=TOOLCLI_ERR_IO, as_json=as_json,
                             error=f"{TOOLCLI_ERR_IO}: {_safe(exc.strerror or exc)[:MAX_SHOWN_PATH_CHARS]}")
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
                     error=f"{missing} name(s) not registered" if missing else None, as_json=as_json)


def _human(result: CliResult) -> List[str]:
    if result.error_code:
        return [result.error or result.error_code]
    d = result.data or {}
    if "usage" in d:
        return d["usage"].splitlines()
    if result.subcommand == "list":
        return [f"{e['canonical']:<36} {e['category']:<14} {e['effect']:<11} "
                f"{'irreversible' if e['irreversible'] else '-':<12} {e['scope_kind']}" for e in d["entries"]] + \
               [f"{d['count']} tool(s)"]
    if result.subcommand == "get":
        e = d["entry"]
        head = "registered" if d["registered"] else "NOT REGISTERED (fail-closed profile)"
        return [f"{e['canonical']}: {head}"] + [f"  {k}: {v}" for k, v in e.items() if k != "canonical"]
    if result.subcommand == "decide":
        flat = [(k, v) for k, v in d.items() if k != "policy"] +                [(f"policy.{k}", v) for k, v in (d.get("policy") or {}).items()]
        return [f"  {k}: {v!r}" if isinstance(v, str) and k.endswith("suffix") else f"  {k}: {v}" for k, v in flat]
    if result.subcommand == "check":
        return [f"{'ok  ' if r['registered'] else 'MISSING'} {r['name']} -> {r['canonical']}"
                f"{'  (grant)' if r['requires_grant'] else ''}" for r in d["names"]]
    if result.subcommand == "export":
        return [f"wrote {d['bytes']} bytes to {_shown(d['path'])} (sha256 {d['sha256']})"]
    return []


def _silence_stdout() -> None:
    """After a closed pipe, point fd 1 at devnull so the interpreter's final flush cannot raise again."""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    except (OSError, ValueError, AttributeError):
        pass


def _emit(text: str, stream: Any) -> bool:
    """Writes one line; False if the stream is gone or closed (pipe closed, fd 1 closed, pythonw).

    Windows reports a closed pipe as OSError(EINVAL), not BrokenPipeError (T-03389 #1, #4).
    """
    if stream is None:
        return False
    try:
        stream.write(text + "\n")
        stream.flush()
        return True
    except (BrokenPipeError, OSError, ValueError):
        return False


def main(argv: Optional[List[str]] = None) -> int:
    """Console entry point; returns the process exit code."""
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        result = dispatch_cli(args)
    except KeyboardInterrupt:
        # Ctrl-C: no traceback; nothing to undo (read-only, and export cleans its temp file itself)
        _emit(f"{TOOLCLI_ERR_INTERRUPTED}: interrupted", sys.stderr)
        return EXIT_INTERRUPTED
    if result.as_json:
        lines, stream = [json.dumps(result.to_dict(), ensure_ascii=True, sort_keys=True)], sys.stdout
    elif result.subcommand == "export" and result.data and "export" in result.data:
        lines, stream = [result.data["export"]], sys.stdout              # exactly the export (ASCII), for piping
    else:
        # every error goes to stderr, so `export > file` can never write an error into the data file (#8)
        stream = sys.stderr if result.error_code else sys.stdout
        lines = [_safe(line) for line in _human(result)]
    for line in lines:
        if not _emit(line, stream):
            if stream is sys.stdout:
                _silence_stdout()
            break                       # reader went away: stop quietly, keep the real exit code (#12)
    return result.exit_code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
