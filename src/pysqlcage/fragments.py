from __future__ import annotations

import weakref
from typing import Any, Iterable, Tuple

from .constants import CODE
from .errors import fail

_FRAGMENT_TOKEN = object()
_PARAM_TOKEN = object()
_FRAGMENT_DATA = weakref.WeakKeyDictionary()


class SqlFragment:
    """Immutable trusted SQL fragment.

    Instances can only be constructed through this module because construction
    requires a private token. The exact-class and token checks in
    is_sql_fragment prevent dictionaries, JSON values, pickle copies, and
    subclass impostors from being accepted as trusted SQL.
    """

    __slots__ = ("__weakref__",)

    def __init_subclass__(cls, **kwargs: Any) -> None:
        raise TypeError("SqlFragment cannot be subclassed")

    def __init__(self, strings: Iterable[str], values: Iterable[Any], *, token: object = None) -> None:
        if token is not _FRAGMENT_TOKEN:
            fail(CODE["INVALID_FRAGMENT"], "SqlFragment instances must be created by pysqlcage factories")
        string_tuple = tuple(strings)
        value_tuple = tuple(values)
        if len(string_tuple) != len(value_tuple) + 1:
            fail(CODE["INVALID_FRAGMENT"], "a SQL fragment requires len(strings) to equal len(values) + 1")
        for text in string_tuple:
            if type(text) is not str:
                fail(CODE["INVALID_FRAGMENT"], "SQL fragment template strings must be exact strings")
        _FRAGMENT_DATA[self] = (string_tuple, value_tuple)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("SqlFragment is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("SqlFragment is immutable")

    @property
    def strings(self) -> Tuple[str, ...]:
        return _FRAGMENT_DATA[self][0]

    @property
    def values(self) -> Tuple[Any, ...]:
        return _FRAGMENT_DATA[self][1]

    def __repr__(self) -> str:
        return "SqlFragment(strings={}, values={})".format(len(self.strings), len(self.values))


class SqlParam:
    """Immutable marker that makes a dynamic value explicit in sql_fragment."""

    __slots__ = ("_param_token", "_value")

    def __init_subclass__(cls, **kwargs: Any) -> None:
        raise TypeError("SqlParam cannot be subclassed")

    def __init__(self, value: Any, *, token: object = None) -> None:
        if token is not _PARAM_TOKEN:
            fail(CODE["INVALID_PARAMETER"], "SqlParam instances must be created by sql_param")
        object.__setattr__(self, "_param_token", _PARAM_TOKEN)
        object.__setattr__(self, "_value", value)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("SqlParam is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("SqlParam is immutable")

    @property
    def value(self) -> Any:
        return object.__getattribute__(self, "_value")

    def __repr__(self) -> str:
        return "SqlParam(<{}>)".format(type(self.value).__name__)


def sql_param(value: Any) -> SqlParam:
    return SqlParam(value, token=_PARAM_TOKEN)


def is_sql_param(value: Any) -> bool:
    if type(value) is not SqlParam:
        return False
    try:
        return object.__getattribute__(value, "_param_token") is _PARAM_TOKEN
    except AttributeError:
        return False


def is_sql_fragment(value: Any) -> bool:
    return type(value) is SqlFragment and value in _FRAGMENT_DATA


def assert_fragment(value: Any, name: str) -> SqlFragment:
    if not is_sql_fragment(value):
        fail(
            CODE["INVALID_FRAGMENT"],
            name + " must be a SQL fragment created by sql_fragment or a pysqlcage helper",
        )
    return value


def create_fragment(strings: Iterable[str], values: Iterable[Any]) -> SqlFragment:
    return SqlFragment(strings, values, token=_FRAGMENT_TOKEN)


def static_fragment(text: str) -> SqlFragment:
    if type(text) is not str:
        fail(CODE["INVALID_FRAGMENT"], "static SQL text must be an exact string")
    return create_fragment((text,), ())


def sql_fragment(*parts: Any) -> SqlFragment:
    """Build a trusted fragment from trusted strings, nested fragments, and sql_param markers.

    Plain strings are developer-controlled SQL template text. Dynamic values
    must be wrapped in sql_param. Nested SqlFragment values are inlined by the
    iterative compiler rather than serialized into SQL text.
    """

    strings = [""]
    values = []
    for part in parts:
        if type(part) is str:
            strings[-1] += part
        elif is_sql_param(part):
            values.append(part.value)
            strings.append("")
        elif is_sql_fragment(part):
            values.append(part)
            strings.append("")
        else:
            fail(
                CODE["INVALID_FRAGMENT"],
                "sql_fragment parts must be strings, sql_param markers, or SQL fragments; wrap dynamic values in sql_param",
            )
    return create_fragment(strings, values)


sql = sql_fragment
