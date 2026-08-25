"""Command-line interface: verify, inspect, and proxy.

    dvarapala verify audit.jsonl
    dvarapala verify --strict audit.jsonl      # require chain anchor
    dvarapala tail audit.jsonl -n 20
    dvarapala anchor audit.jsonl               # re-anchor after pruning
    dvarapala proxy --config p.json -- node server.js
"""
from __future__ import annotations

import argparse
import sys

from .audit import AuditLog


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "proxy":
        return _proxy_main(args[1:])

    parser = argparse.ArgumentParser(
        prog="dvarapala",
        description="Permission gates and tamper-evident audit logs "
                    "for AI agents.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_verify = sub.add_parser("verify", help="verify an audit log's hash chain")
    p_verify.add_argument("path", help="path to audit JSONL file")
    p_verify.add_argument("--strict", action="store_true",
                          help="fail unless a chain anchor (.head) exists "
                               "and matches the log tip")

    p_tail = sub.add_parser("tail", help="show recent audit records")
    p_tail.add_argument("path", help="path to audit JSONL file")
    p_tail.add_argument("-n", type=int, default=20, help="number of records")

    p_anchor = sub.add_parser("anchor",
                              help="re-anchor the chain head to the "
                                   "current tip (after intentional pruning)")
    p_anchor.add_argument("path", help="path to audit JSONL file")

    ns = parser.parse_args(args)
    log = AuditLog(ns.path)

    if ns.command == "verify":
        ok, msg = log.verify(strict=ns.strict)
        print(("OK: " if ok else "FAILED: ") + msg)
        return 0 if ok else 1

    if ns.command == "anchor":
        try:
            tip = log.refresh_anchor()
        except ValueError as exc:
            print(f"FAILED: {exc}")
            return 1
        print(f"anchored: {tip}")
        return 0

    records = log.tail(ns.n)
    if not records:
        print("(no records)")
        return 0
    for rec in records:
        print(rec.brief())
        print()
    return 0


def _proxy_main(rest: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="dvarapala proxy",
        description="Gate any stdio MCP server through Dvarapala.")
    parser.add_argument("--config", help="policy JSON/YAML path")
    parser.add_argument("--audit", help="audit JSONL path")
    parser.add_argument("--no-hide-denied", action="store_true",
                        help="keep denied tools visible in tools/list")
    parser.add_argument("--confirmer", choices=["cli", "auto", "deny"],
                        default=None,
                        help="confirmation backend (default: auto-detect TTY)")
    parser.add_argument("server_cmd", nargs=argparse.REMAINDER,
                        help="-- <command> of the MCP server to wrap")
    ns = parser.parse_args(rest)

    if not ns.server_cmd or ns.server_cmd[0] != "--":
        parser.error("a server command is required: "
                     "dvarapala proxy [options] -- <server command>")
    server_cmd = ns.server_cmd[1:]
    if not server_cmd:
        parser.error("empty server command after '--'")

    from .gate import Gate
    from .proxy import serve

    gate = Gate(policy=ns.config, audit=ns.audit, confirmer=ns.confirmer)
    return serve(server_cmd, gate, hide_denied=not ns.no_hide_denied)


if __name__ == "__main__":
    sys.exit(main())
