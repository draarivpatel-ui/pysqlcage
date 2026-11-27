from __future__ import annotations

import re
from typing import Any

from .constants import CODE, DIALECTS
from .errors import fail

IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
FORBIDDEN_IDENTIFIER_NAMES = frozenset(("__proto__", "constructor", "prototype"))


def normalize_dialect(dialect: Any = None) -> str:
    value = "postgres" if dialect is None else dialect
    if type(value) is not str or value not in DIALECTS:
        fail(CODE["INVALID_DIALECT"], "dialect must be one of postgres, mysql, or sqlite")
    return value


def is_valid_identifier(name: Any) -> bool:
    return (
        type(name) is str
        and IDENTIFIER_RE.fullmatch(name) is not None
        and name.lower() not in FORBIDDEN_IDENTIFIER_NAMES
    )


def assert_identifier(name: Any, role: str = "identifier") -> str:
    if not is_valid_identifier(name):
        fail(
            CODE["INVALID_IDENTIFIER"],
            role + " must be an ASCII SQL identifier matching [A-Za-z_][A-Za-z0-9_]{0,62} and must not be a dangerous cross-stack name",
        )
    return name


def quote_identifier(name: Any, dialect: Any = None) -> str:
    selected = normalize_dialect(dialect)
    assert_identifier(name, "identifier")
    if selected == "mysql":
        return "`" + name + "`"
    return '"' + name + '"'


def qualified_identifier(column: Any, dialect: Any = None, table: Any = None) -> str:
    quoted_column = quote_identifier(column, dialect)
    if table is None:
        return quoted_column
    return quote_identifier(table, dialect) + "." + quoted_column
