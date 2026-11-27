from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import unicodedata
from typing import Any, Optional, Sequence, Tuple

from .audit import audit_sql_query
from .constants import DEFAULT_MAX_SQL_LENGTH, MAX_AUDIT_INPUT_LENGTH, PYSQLCAGE_VERSION
from .errors import SqlCageError

MAX_INPUT_BYTES = 1048576


class _InputError(Exception):
    pass


class _NeutralizingArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, _neutralize(self.prog) + ": error: " + _neutralize(message) + "\n")


def _neutralize(text: Any) -> str:
    value = str(text)
    output = []
    for character in value:
        code = ord(character)
        if character == "\n":
            output.append("\\n")
        elif character == "\r":
            output.append("\\r")
        elif character == "\t":
            output.append("\\t")
        elif code < 32 or code == 127 or unicodedata.category(character) in ("Cf", "Cc"):
            if code <= 0xFF:
                output.append("\\x{:02x}".format(code))
            else:
                output.append("\\u{:04x}".format(code))
        else:
            output.append(character)
    return "".join(output)


def _file_kind(mode: int) -> str:
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISFIFO(mode):
        return "FIFO"
    if stat.S_ISCHR(mode):
        return "character device"
    if stat.S_ISBLK(mode):
        return "block device"
    if stat.S_ISSOCK(mode):
        return "socket"
    if not stat.S_ISREG(mode):
        return "non-regular file"
    return "regular file"


def _read_regular_file(path: str) -> bytes:
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise _InputError("cannot inspect input file " + _neutralize(path) + ": " + _neutralize(exc.strerror or exc))
    kind = _file_kind(before.st_mode)
    if kind != "regular file":
        raise _InputError("input file " + _neutralize(path) + " is a " + kind + "; only regular files are accepted")
    if before.st_size > MAX_INPUT_BYTES:
        raise _InputError("input file " + _neutralize(path) + " exceeds the " + str(MAX_INPUT_BYTES) + " byte limit")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise _InputError("cannot open input file " + _neutralize(path) + ": " + _neutralize(exc.strerror or exc))
    try:
        after = os.fstat(descriptor)
        if not stat.S_ISREG(after.st_mode):
            raise _InputError("input file " + _neutralize(path) + " is not a regular file after opening")
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise _InputError("input file " + _neutralize(path) + " changed while opening")
        if after.st_size > MAX_INPUT_BYTES:
            raise _InputError("input file " + _neutralize(path) + " exceeds the " + str(MAX_INPUT_BYTES) + " byte limit")
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = -1
            data = handle.read(MAX_INPUT_BYTES + 1)
        if len(data) > MAX_INPUT_BYTES:
            raise _InputError("input file " + _neutralize(path) + " exceeds the " + str(MAX_INPUT_BYTES) + " byte limit")
        return data
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_input(path: str) -> Tuple[str, str]:
    if path == "-":
        data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(data) > MAX_INPUT_BYTES:
            raise _InputError("standard input exceeds the " + str(MAX_INPUT_BYTES) + " byte limit")
        label = "<stdin>"
    else:
        data = _read_regular_file(path)
        label = path
    try:
        return data.decode("utf-8", errors="strict"), label
    except UnicodeDecodeError as exc:
        raise _InputError("input " + _neutralize(label) + " is not valid UTF-8: " + _neutralize(exc))


def _parse_max_sql_length(raw: str) -> int:
    if not raw or not raw.isascii() or not raw.isdigit():
        raise _InputError(
            "invalid --max-sql-length value "
            + _neutralize(raw)
            + ": must be an integer between 1 and "
            + str(MAX_AUDIT_INPUT_LENGTH)
        )
    value = int(raw, 10)
    if value < 1 or value > MAX_AUDIT_INPUT_LENGTH:
        raise _InputError(
            "invalid --max-sql-length value "
            + _neutralize(raw)
            + ": must be an integer between 1 and "
            + str(MAX_AUDIT_INPUT_LENGTH)
        )
    return value


def _parser() -> argparse.ArgumentParser:
    parser = _NeutralizingArgumentParser(
        prog="pysqlcage",
        description="Audit SQL text for injection-oriented lexical risk markers.",
    )
    parser.add_argument("--version", action="version", version="pysqlcage " + PYSQLCAGE_VERSION)
    subparsers = parser.add_subparsers(dest="command", required=True, parser_class=_NeutralizingArgumentParser)
    audit = subparsers.add_parser("audit", help="audit one SQL file or standard input")
    audit.add_argument("input", help="SQL file path, or - for standard input")
    audit.add_argument("--dialect", choices=("postgres", "mysql", "sqlite"), default="postgres")
    audit.add_argument(
        "--max-sql-length",
        default=None,
        help="maximum SQL character length before reporting PYSQLCAGE_MAX_SQL_LENGTH (1 to "
        + str(MAX_AUDIT_INPUT_LENGTH)
        + ", default "
        + str(DEFAULT_MAX_SQL_LENGTH)
        + ")",
    )
    audit.add_argument("--json", action="store_true", help="write machine-readable JSON")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command == "audit":
        try:
            max_sql_length = (
                DEFAULT_MAX_SQL_LENGTH
                if args.max_sql_length is None
                else _parse_max_sql_length(args.max_sql_length)
            )
            query, label = _read_input(args.input)
            result = audit_sql_query(query, dialect=args.dialect, max_sql_length=max_sql_length)
        except (_InputError, SqlCageError) as exc:
            print("pysqlcage: error: " + _neutralize(exc), file=sys.stderr)
            return 2
        if args.json:
            payload = result.to_dict()
            payload["dialect"] = args.dialect
            payload["input"] = "<stdin>" if label == "<stdin>" else _neutralize(label)
            print(json.dumps(payload, ensure_ascii=True, sort_keys=True))
        elif result.safe:
            print("safe: no SQL injection risk findings")
        else:
            print("unsafe: " + str(len(result.findings)) + " finding(s)")
            for finding in result.findings:
                token = "" if finding.token is None else " token " + _neutralize(finding.token)
                print("- " + finding.code + " at " + str(finding.index) + token + ": " + _neutralize(finding.message))
        return 0 if result.safe else 1
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    sys.exit(main())
