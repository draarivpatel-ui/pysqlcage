from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, Iterable, List, NamedTuple, Optional, Sequence, Tuple

from .constants import (
    CODE,
    DEFAULT_MAX_LIMIT,
    DEFAULT_MAX_PARAMETERS,
    MAX_LIMIT_OFFSET,
    MAX_ORDER_CLAUSES,
    MAX_SCHEMA_COLUMNS,
    MAX_SET_COLUMNS,
    MAX_VALUES_ROWS,
)
from .errors import fail
from .fragments import assert_fragment, is_sql_fragment, sql_fragment, sql_param, static_fragment
from .identifiers import assert_identifier, normalize_dialect, qualified_identifier, quote_identifier

_COLUMN_SENTINEL = object()
_LIKE_ESCAPE_CHARS = frozenset(("\\", "!", "@", "#", "^", "~", "|"))
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_COMMA_JOIN_RE = re.compile(r"^\s*,\s*$")
_LOGIC_JOIN_RE = re.compile(r"^\s+(?:AND|OR)\s+$", re.IGNORECASE)


def _validate_cap(name: str, value: Any, default: int, maximum: int) -> int:
    candidate = default if value is None else value
    if type(candidate) is not int or candidate < 1 or candidate > maximum:
        fail(CODE["INVALID_OPTIONS"], name + " must be an integer between 1 and " + str(maximum))
    return candidate


def _sequence(value: Any, name: str, code: str) -> Sequence[Any]:
    if type(value) not in (list, tuple):
        fail(code, name + " must be a list or tuple")
    return value


def _mapping(value: Any, name: str, code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        fail(code, name + " must be a mapping")
    return value


def _normalize_allowed_columns(allowed_columns: Any) -> frozenset:
    if type(allowed_columns) not in (list, tuple, set, frozenset):
        fail(CODE["INVALID_SCHEMA"], "allowed_columns must be a list, tuple, set, or frozenset of SQL identifiers")
    result = []
    seen = set()
    for column in allowed_columns:
        assert_identifier(column, "allowed column")
        if column in seen:
            fail(CODE["INVALID_SCHEMA"], "allowed column " + column + " repeats")
        seen.add(column)
        result.append(column)
    return frozenset(result)


def safe_columns(
    columns: Any,
    allowed_columns: Any,
    *,
    dialect: Any = None,
    table: Any = None,
    max_columns: Any = None,
) -> Any:
    selected = normalize_dialect(dialect)
    if table is not None:
        assert_identifier(table, "table")
    allowed = _normalize_allowed_columns(allowed_columns)
    items = _sequence(columns, "columns", CODE["EMPTY_COLUMN_LIST"])
    if len(items) == 0:
        fail(CODE["EMPTY_COLUMN_LIST"], "columns must not be empty")
    cap = _validate_cap("max_columns", max_columns, MAX_SCHEMA_COLUMNS, 1024)
    seen = set()
    rendered = []
    for column in items:
        assert_identifier(column, "column")
        if column not in allowed:
            fail(CODE["UNKNOWN_COLUMN"], "column is not in the allowlist", {"column": column})
        if column in seen:
            continue
        seen.add(column)
        rendered.append(qualified_identifier(column, selected, table))
        if len(rendered) > cap:
            fail(CODE["INVALID_OPTIONS"], "column count exceeds max_columns (" + str(cap) + ")")
    return static_fragment(", ".join(rendered))


def _normalize_direction(value: Any) -> str:
    if value is None:
        return "ASC"
    if type(value) is not str:
        fail(CODE["INVALID_ORDER_BY"], "ORDER BY direction must be ASC or DESC")
    normalized = value.upper()
    if normalized not in ("ASC", "DESC"):
        fail(CODE["INVALID_ORDER_BY"], "ORDER BY direction must be ASC or DESC")
    return normalized


def _normalize_nulls(value: Any) -> Optional[str]:
    if value is None:
        return None
    if type(value) is not str:
        fail(CODE["INVALID_ORDER_BY"], "ORDER BY nulls must be FIRST or LAST")
    normalized = value.upper().replace("-", "_").replace(" ", "_")
    if normalized.startswith("NULLS_"):
        normalized = normalized[6:]
    if normalized not in ("FIRST", "LAST"):
        fail(CODE["INVALID_ORDER_BY"], "ORDER BY nulls must be FIRST or LAST")
    return normalized


def _parse_order_string(text: str) -> List[Tuple[Any, Any, Any]]:
    clauses = []
    for raw_piece in text.split(","):
        piece = raw_piece.strip()
        if not piece:
            fail(CODE["INVALID_ORDER_BY"], "ORDER BY string must not contain empty clauses")
        parts = [part.strip() for part in piece.split(":")]
        if len(parts) > 3 or not parts[0]:
            fail(CODE["INVALID_ORDER_BY"], "ORDER BY string clauses must use column[:asc|desc[:nulls-first|nulls-last]]")
        nulls = None
        if len(parts) == 3:
            nulls = parts[2].replace("nulls-", "").replace("nulls_", "")
        clauses.append((parts[0], parts[1] if len(parts) > 1 else None, nulls))
    return clauses


def _normalize_order_items(clauses: Any) -> List[Tuple[Any, Any, Any]]:
    if type(clauses) is str:
        return _parse_order_string(clauses)
    items = _sequence(clauses, "ORDER BY clauses", CODE["INVALID_ORDER_BY"])
    normalized = []
    for clause in items:
        if type(clause) is str:
            if "," in clause or ":" in clause:
                normalized.extend(_parse_order_string(clause))
            else:
                normalized.append((clause, None, None))
        elif isinstance(clause, Mapping):
            normalized.append((clause.get("column"), clause.get("direction"), clause.get("nulls")))
        elif type(clause) in (list, tuple) and 1 <= len(clause) <= 3:
            column = clause[0]
            direction = clause[1] if len(clause) > 1 else None
            nulls = clause[2] if len(clause) > 2 else None
            normalized.append((column, direction, nulls))
        else:
            fail(CODE["INVALID_ORDER_BY"], "each ORDER BY clause must be a column string, mapping, or tuple")
    return normalized


def safe_order_by(
    clauses: Any,
    allowed_columns: Any,
    *,
    dialect: Any = None,
    table: Any = None,
    max_clauses: Any = None,
) -> Any:
    selected = normalize_dialect(dialect)
    if table is not None:
        assert_identifier(table, "table")
    allowed = _normalize_allowed_columns(allowed_columns)
    parsed_input = _normalize_order_items(clauses)
    if len(parsed_input) == 0:
        fail(CODE["EMPTY_ORDER_BY"], "ORDER BY clauses must not be empty")
    cap = _validate_cap("max_clauses", max_clauses, MAX_ORDER_CLAUSES, 64)
    if len(parsed_input) > cap:
        fail(CODE["INVALID_ORDER_BY"], "ORDER BY clause count exceeds max_clauses (" + str(cap) + ")")
    seen = set()
    terms = []
    for raw_column, raw_direction, raw_nulls in parsed_input:
        column = assert_identifier(raw_column, "ORDER BY column")
        if column not in allowed:
            fail(CODE["UNKNOWN_COLUMN"], "ORDER BY column is not sortable", {"column": column})
        if column in seen:
            fail(CODE["INVALID_ORDER_BY"], "ORDER BY columns must not repeat", {"column": column})
        seen.add(column)
        direction = _normalize_direction(raw_direction)
        nulls = _normalize_nulls(raw_nulls)
        if nulls is not None and selected == "mysql":
            fail(CODE["INVALID_ORDER_BY"], "MySQL does not support ORDER BY NULLS FIRST or NULLS LAST syntax")
        term = qualified_identifier(column, selected, table) + " " + direction
        if nulls is not None:
            term += " NULLS " + nulls
        terms.append(term)
    return static_fragment("ORDER BY " + ", ".join(terms))


def _plain_nonbool_int(value: Any) -> bool:
    return type(value) is int


def safe_limit_offset(limit: Any = None, offset: Any = 0, max_limit: Any = None) -> Any:
    if isinstance(limit, Mapping) and offset == 0 and max_limit is None:
        spec = limit
        limit = spec.get("limit")
        offset = spec.get("offset", 0)
        max_limit = spec.get("max_limit", spec.get("maxLimit"))
    elif isinstance(limit, Mapping):
        fail(CODE["INVALID_LIMIT_OFFSET"], "limit mapping input cannot be combined with positional offset or max_limit")
    configured_max = DEFAULT_MAX_LIMIT if max_limit is None else max_limit
    if not _plain_nonbool_int(configured_max) or configured_max < 1 or configured_max > MAX_LIMIT_OFFSET:
        fail(CODE["INVALID_LIMIT_OFFSET"], "max_limit must be a positive integer")
    if not _plain_nonbool_int(limit) or limit < 1 or limit > configured_max:
        fail(CODE["INVALID_LIMIT_OFFSET"], "limit must be an integer between 1 and max_limit")
    if not _plain_nonbool_int(offset) or offset < 0 or offset > MAX_LIMIT_OFFSET:
        fail(CODE["INVALID_LIMIT_OFFSET"], "offset must be a non-negative integer")
    normalized_offset = 0 if offset == 0 else offset
    return sql_fragment("LIMIT ", sql_param(limit), " OFFSET ", sql_param(normalized_offset))


def validate_join_separator(separator: Any) -> str:
    if type(separator) is not str or not separator or len(separator) > 32:
        fail(CODE["INVALID_JOIN_SEPARATOR"], "join separator must be a non-empty string of at most 32 characters")
    if _CONTROL_RE.search(separator):
        fail(CODE["INVALID_JOIN_SEPARATOR"], "join separator must not contain control characters")
    if _COMMA_JOIN_RE.fullmatch(separator) or _LOGIC_JOIN_RE.fullmatch(separator):
        return separator
    fail(CODE["INVALID_JOIN_SEPARATOR"], "join separator must be a comma or a whitespace-separated AND/OR operator")
    return separator


def sql_join(parts: Any, separator: Any = ", ") -> Any:
    items = _sequence(parts, "sql_join parts", CODE["INVALID_INPUT"])
    joiner = validate_join_separator(separator)
    for part in items:
        assert_fragment(part, "sql_join part")
    if not items:
        return static_fragment("")
    assembled = []
    for index, part in enumerate(items):
        if index:
            assembled.append(joiner)
        assembled.append(part)
    return sql_fragment(*assembled)


def _wrap_conditions(parts: Any, joiner: str) -> Any:
    items = _sequence(parts, "condition list", CODE["EMPTY_CONDITION_LIST"])
    if not items:
        fail(CODE["EMPTY_CONDITION_LIST"], "condition list must not be empty")
    wrapped = []
    for part in items:
        assert_fragment(part, "condition")
        wrapped.append(sql_fragment("(", part, ")"))
    return sql_join(wrapped, joiner)


def sql_and(parts: Any) -> Any:
    return _wrap_conditions(parts, " AND ")


def sql_or(parts: Any) -> Any:
    return _wrap_conditions(parts, " OR ")


def _column_to_fragment(column: Any, dialect: str) -> Any:
    if is_sql_fragment(column):
        return column
    if type(column) is str:
        return static_fragment(quote_identifier(column, dialect))
    fail(CODE["INVALID_IDENTIFIER"], "column must be a SQL identifier string or a schema-guard SQL fragment")


def sql_in(
    column_or_values: Any,
    values: Any = _COLUMN_SENTINEL,
    *,
    dialect: Any = None,
    on_empty: Any = "throw",
    max_parameters: Any = None,
) -> Any:
    selected = normalize_dialect(dialect)
    if values is _COLUMN_SENTINEL:
        column = None
        items_input = column_or_values
    else:
        column = column_or_values
        items_input = values
    items = _sequence(items_input, "sql_in values", CODE["INVALID_INPUT"])
    if on_empty not in ("throw", "false"):
        fail(CODE["INVALID_OPTIONS"], "sql_in on_empty must be throw or false")
    cap = _validate_cap("max_parameters", max_parameters, DEFAULT_MAX_PARAMETERS, DEFAULT_MAX_PARAMETERS)
    if len(items) > cap:
        fail(CODE["MAX_PARAMETERS"], "IN list item count exceeds max_parameters (" + str(cap) + ")")
    if len(items) == 0:
        if on_empty == "false":
            return static_fragment("1 = 0")
        fail(CODE["EMPTY_IN_LIST"], "IN lists must not be empty")
    parts = []
    if column is not None:
        parts.extend((_column_to_fragment(column, selected), " IN ("))
    else:
        parts.append("IN (")
    for index, value in enumerate(items):
        if index:
            parts.append(", ")
        parts.append(sql_param(value))
    parts.append(")")
    return sql_fragment(*parts)


def sql_values(
    rows: Any,
    *,
    columns: Any = None,
    max_rows: Any = None,
    max_parameters: Any = None,
) -> Any:
    row_items = _sequence(rows, "VALUES rows", CODE["EMPTY_VALUES"])
    if len(row_items) == 0:
        fail(CODE["EMPTY_VALUES"], "VALUES rows must be a non-empty list or tuple")
    row_cap = _validate_cap("max_rows", max_rows, MAX_VALUES_ROWS, 10000)
    param_cap = _validate_cap("max_parameters", max_parameters, DEFAULT_MAX_PARAMETERS, DEFAULT_MAX_PARAMETERS)
    if len(row_items) > row_cap:
        fail(CODE["EMPTY_VALUES"], "VALUES row count exceeds max_rows (" + str(row_cap) + ")")
    first = row_items[0]
    first_is_mapping = isinstance(first, Mapping)
    first_is_sequence = type(first) in (list, tuple)
    if not first_is_mapping and not first_is_sequence:
        fail(CODE["EMPTY_VALUES"], "VALUES rows must be sequences or mappings")
    width = 0
    column_list = None
    if first_is_sequence:
        width = len(first)
        if width == 0:
            fail(CODE["EMPTY_VALUES"], "VALUES rows must not be empty")
        for row in row_items:
            if type(row) not in (list, tuple) or len(row) != width:
                fail(CODE["EMPTY_VALUES"], "all VALUES sequence rows must have the same non-zero width")
    else:
        if columns is None:
            column_list = list(first.keys())
        else:
            column_list = list(_sequence(columns, "VALUES columns", CODE["EMPTY_VALUES"]))
        if not column_list:
            fail(CODE["EMPTY_VALUES"], "VALUES object rows must have at least one column")
        seen_columns = set()
        for column in column_list:
            assert_identifier(column, "VALUES column")
            if column in seen_columns:
                fail(CODE["EMPTY_VALUES"], "VALUES columns must not repeat")
            seen_columns.add(column)
        for row in row_items:
            if not isinstance(row, Mapping):
                fail(CODE["EMPTY_VALUES"], "all VALUES object rows must be mappings")
            keys = list(row.keys())
            if len(keys) != len(column_list) or any(key not in seen_columns for key in keys):
                fail(CODE["EMPTY_VALUES"], "all VALUES object rows must exactly match the column list")
        width = len(column_list)
    if width * len(row_items) > param_cap:
        fail(CODE["MAX_PARAMETERS"], "VALUES parameter count exceeds max_parameters (" + str(param_cap) + ")")
    parts = ["VALUES "]
    for row_index, row in enumerate(row_items):
        if row_index:
            parts.append(", ")
        parts.append("(")
        for column_index in range(width):
            if column_index:
                parts.append(", ")
            value = row[column_index] if column_list is None else row[column_list[column_index]]
            parts.append(sql_param(value))
        parts.append(")")
    return sql_fragment(*parts)


def sql_set(
    assignments: Any,
    *,
    dialect: Any = None,
    allowed_columns: Any = None,
    max_columns: Any = None,
) -> Any:
    selected = normalize_dialect(dialect)
    mapping = _mapping(assignments, "sql_set assignments", CODE["EMPTY_SET"])
    keys = list(mapping.keys())
    if not keys:
        fail(CODE["EMPTY_SET"], "sql_set assignments must not be empty")
    cap = _validate_cap("max_columns", max_columns, MAX_SET_COLUMNS, 1024)
    if len(keys) > cap:
        fail(CODE["EMPTY_SET"], "sql_set column count exceeds max_columns (" + str(cap) + ")")
    allowed = None if allowed_columns is None else _normalize_allowed_columns(allowed_columns)
    parts = ["SET "]
    for index, column in enumerate(keys):
        assert_identifier(column, "SET column")
        if allowed is not None and column not in allowed:
            fail(CODE["UNKNOWN_COLUMN"], "SET column is not in the allowlist", {"column": column})
        if index:
            parts.append(", ")
        parts.extend((quote_identifier(column, selected) + " = ", sql_param(mapping[column])))
    return sql_fragment(*parts)


class EscapedLikePattern(NamedTuple):
    pattern: str
    escape_char: str


def _assert_like_escape_char(value: Any) -> str:
    if type(value) is not str or value not in _LIKE_ESCAPE_CHARS:
        fail(CODE["INVALID_LIKE_PATTERN"], "LIKE escape character must be one of \\, !, @, #, ^, ~, or |")
    return value


def escape_like_pattern(value: Any, escape_char: Any = "\\") -> EscapedLikePattern:
    escape = _assert_like_escape_char(escape_char)
    if type(value) is not str:
        fail(CODE["INVALID_LIKE_PATTERN"], "LIKE input must be a string")
    output = []
    for character in value:
        if character == escape or character in ("%", "_"):
            output.append(escape + character)
        else:
            output.append(character)
    return EscapedLikePattern("".join(output), escape)


def sql_like(
    column: Any,
    value: Any,
    *,
    dialect: Any = None,
    mode: Any = "contains",
    escape_char: Any = None,
    max_pattern_length: Any = None,
) -> Any:
    selected = normalize_dialect(dialect)
    if type(value) is not str:
        fail(CODE["INVALID_LIKE_PATTERN"], "sql_like value must be a string")
    cap = _validate_cap("max_pattern_length", max_pattern_length, 1024, 65536)
    if len(value) > cap:
        fail(CODE["INVALID_LIKE_PATTERN"], "sql_like value exceeds max_pattern_length (" + str(cap) + ")")
    if type(mode) is not str:
        fail(CODE["INVALID_LIKE_PATTERN"], "sql_like mode must be contains, starts_with, or ends_with")
    mode_key = mode.replace("-", "_")
    if mode_key == "startsWith":
        mode_key = "starts_with"
    if mode_key == "endsWith":
        mode_key = "ends_with"
    if mode_key not in ("contains", "starts_with", "ends_with"):
        fail(CODE["INVALID_LIKE_PATTERN"], "sql_like mode must be contains, starts_with, or ends_with")
    escape = escape_char
    if escape is None:
        escape = "!" if selected == "mysql" else "\\"
    if selected == "mysql" and escape == "\\":
        fail(CODE["INVALID_LIKE_PATTERN"], "MySQL LIKE escape characters must be mode-independent; use a non-backslash escape character")
    escaped = escape_like_pattern(value, escape)
    pattern = escaped.pattern
    if mode_key == "contains":
        pattern = "%" + pattern + "%"
    elif mode_key == "starts_with":
        pattern = pattern + "%"
    else:
        pattern = "%" + pattern
    column_fragment = _column_to_fragment(column, selected)
    return sql_fragment(column_fragment, " LIKE ", sql_param(pattern), " ESCAPE '" + escaped.escape_char + "'")
