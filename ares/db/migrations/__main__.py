"""Noninteractive operator interface for verified database adoption."""
from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from ares.db.migrations.adoption import AdoptionExit, safe_execute


class _HelpRequestedError(Exception):
    pass


class _FixedParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise ValueError

    def exit(self, status: int = 0, message: str | None = None) -> None:
        if status == 0:
            raise _HelpRequestedError
        raise ValueError


def _parser() -> argparse.ArgumentParser:
    parser = _FixedParser(prog="python -m ares.db.migrations")
    subparsers = parser.add_subparsers(dest="operation")
    subparsers.add_parser("verify-adoption")
    subparsers.add_parser("verify-managed")

    adopt = subparsers.add_parser("adopt")
    adopt.add_argument("--confirm-adoption", action="store_true")
    adopt.add_argument("--confirm-external-backup", action="store_true")
    adopt.add_argument("--sqlite-backup")

    restore = subparsers.add_parser("restore-sqlite")
    restore.add_argument("--confirm-restore", action="store_true")
    restore.add_argument("--sqlite-backup")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
    except _HelpRequestedError:
        return int(AdoptionExit.OK)
    except (SystemExit, ValueError):
        print("ARES-M2B-E02:USAGE")
        return int(AdoptionExit.USAGE)
    if args.operation is None:
        parser.print_help()
        return int(AdoptionExit.OK)
    if args.operation == "adopt" and not args.confirm_adoption:
        print("ARES-M2B-E02:USAGE")
        return int(AdoptionExit.USAGE)
    if args.operation == "restore-sqlite" and not args.confirm_restore:
        print("ARES-M2B-E02:USAGE")
        return int(AdoptionExit.USAGE)
    result = safe_execute(
        args.operation,
        sqlite_backup=getattr(args, "sqlite_backup", None),
        external_backup_confirmed=getattr(
            args,
            "confirm_external_backup",
            False,
        ),
    )
    print(result.diagnostic)
    return int(result.exit_code)


if __name__ == "__main__":
    sys.exit(main())
