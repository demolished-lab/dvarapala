"""Command-line interface: verify and inspect audit logs.

    dvarapala verify audit.jsonl
    dvarapala tail audit.jsonl -n 20
"""
from __future__ import annotations

import argparse
import sys

from .audit import AuditLog


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dvarapala",
        description="Permission gates and tamper-evident audit logs "
                    "for AI agents.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_verify = sub.add_parser("verify", help="verify an audit log's hash chain")
    p_verify.add_argument("path", help="path to audit JSONL file")

    p_tail = sub.add_parser("tail", help="show recent audit records")
    p_tail.add_argument("path", help="path to audit JSONL file")
    p_tail.add_argument("-n", type=int, default=20, help="number of records")

    args = parser.parse_args(argv)
    log = AuditLog(args.path)

    if args.command == "verify":
        ok, msg = log.verify()
        print(("OK: " if ok else "FAILED: ") + msg)
        return 0 if ok else 1

    records = log.tail(args.n)
    if not records:
        print("(no records)")
        return 0
    for rec in records:
        print(rec.brief())
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
