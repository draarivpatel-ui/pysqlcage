from __future__ import annotations

import math
from datetime import date, datetime
from decimal import Decimal
from types import MappingProxyType
from typing import Any, Dict, Mapping, Optional, Tuple
from uuid import UUID

from .constants import (
    CODE,
    DEFAULT_MAX_FRAGMENT_DEPTH,
    DEFAULT_MAX_PARAMETERS,
    DEFAULT_MAX_SQL_LENGTH,
    PARAMSTYLES,
)
from .errors import fail
from .fragments import assert_fragment, is_sql_fragment, sql_fragment
from .identifiers import normalize_dialect, quote_identifier

_DEFAULT_PARAMSTYLE = {
    "postgres": "format",
    "mysql": "format",
    "sqlite": "qmark",
}


def normalize_paramstyle(paramstyle: Any, dialect: str) -> str:
    value = _DEFAULT_PARAMSTYLE[dialect] if paramstyle is None else paramstyle
    if type(value) is not str or value not in PARAMSTYLES:
        fail(CODE["INVALID_PARAMSTYLE"], "paramstyle must be one of qmark, format, pyformat, or numeric")
    return value


def _bounded_positive_int(name: str, value: Any, maximum: int) -> int:
    if type(value) is not int or value < 1 or value > maximum:
        fail(CODE["INVALID_OPTIONS"], name + " must be an integer between 1 and " + str(maximum))
    return value


def _compile_settings(
    dialect: Any = None,
    paramstyle: Any = None,
    max_parameters: Any = DEFAULT_MAX_PARAMETERS,
    max_sql_length: Any = DEFAULT_MAX_SQL_LENGTH,
    max_fragment_depth: Any = DEFAULT_MAX_FRAGMENT_DEPTH,
    allow_objects: bool = False,
    allow_callables: bool = False,
    allow_non_finite: bool = False,
) -> Dict[str, Any]:
    selected_dialect = normalize_dialect(dialect)
    for flag_name, flag in (
        ("allow_objects", allow_objects),
        ("allow_callables", allow_callables),
        ("allow_non_finite", allow_non_finite),
    ):
        if type(flag) is not bool:
            fail(CODE["INVALID_OPTIONS"], flag_name + " must be a bool")
    return {
        "dialect": selected_dialect,
        "paramstyle": normalize_paramstyle(paramstyle, selected_dialect),
        "max_parameters": _bounded_positive_int("max_parameters", max_parameters, DEFAULT_MAX_PARAMETERS),
        "max_sql_length": _bounded_positive_int("max_sql_length", max_sql_length, DEFAULT_MAX_SQL_LENGTH),
        "max_fragment_depth": _bounded_positive_int("max_fragment_depth", max_fragment_depth, DEFAULT_MAX_FRAGMENT_DEPTH),
        "allow_objects": allow_objects,
        "allow_callables": allow_callables,
        "allow_non_finite": allow_non_finite,
    }


def _is_safe_scalar(value: Any) -> bool:
    if value is None or type(value) is bool:
        return True
    if type(value) in (int, str, bytes):
        return True
    if type(value) is float:
        return math.isfinite(value)
    if isinstance(value, Decimal):
        return value.is_finite()
    if isinstance(value, (datetime, date, UUID)):
        return True
    return False


def validate_parameter(value: Any, settings: Mapping[str, Any], position: int) -> Any:
    if type(value) is float:
        if math.isfinite(value) or settings["allow_non_finite"]:
            return value
        fail(CODE["INVALID_PARAMETER"], "parameter " + str(position) + " must be a finite number")
    if isinstance(value, Decimal):
        if value.is_finite() or settings["allow_non_finite"]:
            return value
        fail(CODE["INVALID_PARAMETER"], "parameter " + str(position) + " must be a finite Decimal")
    if value is None or type(value) in (bool, int, str, bytes) or isinstance(value, (datetime, date, UUID)):
        return value
    if callable(value):
        if settings["allow_callables"]:
            return value
        fail(CODE["INVALID_PARAMETER"], "parameter " + str(position) + " must not be callable")
    if not settings["allow_objects"]:
        fail(
            CODE["INVALID_PARAMETER"],
            "parameter " + str(position) + " is not a supported scalar; pass None, bool, int, finite float, str, bytes, Decimal, date, datetime, or UUID",
        )
    return value


def _placeholder(paramstyle: str, position: int) -> str:
    if paramstyle == "qmark":
        return "?"
    if paramstyle == "numeric":
        return "$" + str(position)
    return "%s"


def compile_query(
    fragment: Any,
    *,
    dialect: Any = None,
    paramstyle: Any = None,
    max_parameters: Any = DEFAULT_MAX_PARAMETERS,
    max_sql_length: Any = DEFAULT_MAX_SQL_LENGTH,
    max_fragment_depth: Any = DEFAULT_MAX_FRAGMENT_DEPTH,
    allow_objects: bool = False,
    allow_callables: bool = False,
    allow_non_finite: bool = False,
) -> Tuple[str, Tuple[Any, ...]]:
    """Compile a trusted fragment to a ``(sql, tuple_params)`` pair.

    Compilation is iterative. Deeply nested input reaches the configured depth
    cap as a structured SqlCageError instead of recursing through Python frames.
    """

    settings = _compile_settings(
        dialect=dialect,
        paramstyle=paramstyle,
        max_parameters=max_parameters,
        max_sql_length=max_sql_length,
        max_fragment_depth=max_fragment_depth,
        allow_objects=allow_objects,
        allow_callables=allow_callables,
        allow_non_finite=allow_non_finite,
    )
    return _compile_with_settings(fragment, settings)


def _compile_with_settings(fragment: Any, settings: Mapping[str, Any]) -> Tuple[str, Tuple[Any, ...]]:
    root = assert_fragment(fragment, "query")
    sql_parts = []
    values = []
    sql_length = 0

    def append_sql(text: str) -> None:
        nonlocal sql_length
        sql_length += len(text)
        if sql_length > settings["max_sql_length"]:
            fail(CODE["MAX_SQL_LENGTH"], "compiled SQL length exceeds max_sql_length (" + str(settings["max_sql_length"]) + ")")
        sql_parts.append(text)

    def append_parameter(value: Any) -> None:
        position = len(values) + 1
        if len(values) >= settings["max_parameters"]:
            fail(CODE["MAX_PARAMETERS"], "parameter count exceeds max_parameters (" + str(settings["max_parameters"]) + ")")
        values.append(validate_parameter(value, settings, position))
        append_sql(_placeholder(settings["paramstyle"], position))

    stack = [("fragment", root, 0)]
    while stack:
        event_type, payload, depth = stack.pop()
        if event_type == "text":
            append_sql(payload)
            continue
        if event_type == "parameter":
            append_parameter(payload)
            continue
        if depth > settings["max_fragment_depth"]:
            fail(
                CODE["MAX_FRAGMENT_DEPTH"],
                "SQL fragment nesting exceeds max_fragment_depth (" + str(settings["max_fragment_depth"]) + ")",
            )
        data_strings = payload.strings
        data_values = payload.values
        sequence = [("text", data_strings[0], depth)]
        for index, value in enumerate(data_values):
            if is_sql_fragment(value):
                sequence.append(("fragment", value, depth + 1))
            else:
                sequence.append(("parameter", value, depth))
            sequence.append(("text", data_strings[index + 1], depth))
        for event in reversed(sequence):
            stack.append(event)

    return "".join(sql_parts), tuple(values)


class SqlCage:
    """Reusable dialect-specific compiler factory."""

    __slots__ = ("_settings", "_options", "_explicit_paramstyle", "_frozen")

    def __init__(
        self,
        dialect: Any = None,
        *,
        paramstyle: Any = None,
        max_parameters: Any = DEFAULT_MAX_PARAMETERS,
        max_sql_length: Any = DEFAULT_MAX_SQL_LENGTH,
        max_fragment_depth: Any = DEFAULT_MAX_FRAGMENT_DEPTH,
        allow_objects: bool = False,
        allow_callables: bool = False,
        allow_non_finite: bool = False,
    ) -> None:
        settings = _compile_settings(
            dialect=dialect,
            paramstyle=paramstyle,
            max_parameters=max_parameters,
            max_sql_length=max_sql_length,
            max_fragment_depth=max_fragment_depth,
            allow_objects=allow_objects,
            allow_callables=allow_callables,
            allow_non_finite=allow_non_finite,
        )
        object.__setattr__(self, "_settings", settings)
        object.__setattr__(self, "_options", MappingProxyType(dict(settings)))
        object.__setattr__(self, "_explicit_paramstyle", paramstyle is not None)
        object.__setattr__(self, "_frozen", True)

    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_frozen", False):
            raise AttributeError("SqlCage is immutable")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        raise AttributeError("SqlCage is immutable")

    @property
    def dialect(self) -> str:
        return self._settings["dialect"]

    @property
    def paramstyle(self) -> str:
        return self._settings["paramstyle"]

    @property
    def options(self) -> Mapping[str, Any]:
        return self._options

    def compile(self, fragment: Any, **overrides: Any) -> Tuple[str, Tuple[Any, ...]]:
        unknown = sorted(set(overrides) - set(self._settings))
        if unknown:
            fail(CODE["INVALID_OPTIONS"], "unknown compile override " + unknown[0])
        settings = dict(self._settings)
        settings.update(overrides)
        if not self._explicit_paramstyle and "paramstyle" not in overrides:
            settings["paramstyle"] = None
        normalized = _compile_settings(**settings)
        return _compile_with_settings(fragment, normalized)

    def compile_query(self, fragment: Any, **overrides: Any) -> Tuple[str, Tuple[Any, ...]]:
        return self.compile(fragment, **overrides)

    def quote_identifier(self, name: Any) -> str:
        return quote_identifier(name, self.dialect)

    def schema(self, schema_spec: Any, **options: Any) -> Any:
        from .schema import SchemaGuard

        options.setdefault("dialect", self.dialect)
        return SchemaGuard(schema_spec, **options)

    def sql_fragment(self, *parts: Any) -> Any:
        return sql_fragment(*parts)


def create_sql_cage(**options: Any) -> SqlCage:
    return SqlCage(**options)
