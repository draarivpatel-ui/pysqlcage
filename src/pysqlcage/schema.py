from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Dict, Optional, Tuple

from .constants import CODE, DEFAULT_MAX_LIMIT, MAX_ORDER_CLAUSES, MAX_SCHEMA_COLUMNS, MAX_SCHEMA_TABLES
from .errors import fail
from .fragments import static_fragment
from .helpers import safe_columns, safe_limit_offset, safe_order_by, sql_set, sql_values
from .identifiers import assert_identifier, normalize_dialect, qualified_identifier, quote_identifier


@dataclass(frozen=True)
class _TableSpec:
    columns: Tuple[str, ...]
    sortable: Tuple[str, ...]


def _cap(name: str, value: Any, default: int, maximum: int, code: str) -> int:
    candidate = default if value is None else value
    if type(candidate) is not int or candidate < 1 or candidate > maximum:
        fail(code, name + " must be an integer between 1 and " + str(maximum))
    return candidate


def _normalize_table_spec(table_name: str, spec: Any) -> _TableSpec:
    columns_input = None
    sortable_input = None
    sortable_supplied = False
    if type(spec) in (list, tuple):
        columns_input = spec
    elif isinstance(spec, Mapping):
        if "columns" in spec:
            columns_input = spec["columns"]
        if "sortable" in spec:
            sortable_input = spec["sortable"]
            sortable_supplied = True
        elif "sortable_columns" in spec:
            sortable_input = spec["sortable_columns"]
            sortable_supplied = True
    else:
        fail(CODE["INVALID_SCHEMA"], "schema table " + table_name + " must be a column list or a mapping with columns")
    if type(columns_input) not in (list, tuple) or len(columns_input) == 0:
        fail(CODE["INVALID_SCHEMA"], "schema table " + table_name + " must declare at least one column")
    columns = []
    column_set = set()
    for column in columns_input:
        assert_identifier(column, "schema column")
        if column in column_set:
            fail(CODE["INVALID_SCHEMA"], "schema table " + table_name + " repeats column " + column)
        column_set.add(column)
        columns.append(column)
    if not sortable_supplied:
        sortable = list(columns)
    else:
        if type(sortable_input) not in (list, tuple):
            fail(CODE["INVALID_SCHEMA"], "schema table " + table_name + " sortable must be a list or tuple")
        sortable = []
        sortable_set = set()
        for column in sortable_input:
            assert_identifier(column, "sortable column")
            if column not in column_set:
                fail(CODE["INVALID_SCHEMA"], "schema table " + table_name + " sortable column " + column + " is not a declared column")
            if column in sortable_set:
                fail(CODE["INVALID_SCHEMA"], "schema table " + table_name + " repeats sortable column " + column)
            sortable_set.add(column)
            sortable.append(column)
    return _TableSpec(tuple(columns), tuple(sortable))


class SchemaGuard:
    """Immutable table, column, sorting, pagination, SET, and VALUES allowlist."""

    __slots__ = (
        "_dialect",
        "_tables",
        "_specs",
        "_max_columns",
        "_max_clauses",
        "_max_limit",
        "_frozen",
    )

    def __init__(
        self,
        schema: Any,
        *,
        dialect: Any = None,
        max_tables: Any = None,
        max_columns: Any = None,
        max_clauses: Any = None,
        max_limit: Any = None,
    ) -> None:
        selected = normalize_dialect(dialect)
        if not isinstance(schema, Mapping):
            fail(CODE["INVALID_SCHEMA"], "schema must be a mapping of table names to column definitions")
        table_names = list(schema.keys())
        if not table_names:
            fail(CODE["INVALID_SCHEMA"], "schema must declare at least one table")
        table_cap = _cap("max_tables", max_tables, MAX_SCHEMA_TABLES, 4096, CODE["INVALID_SCHEMA"])
        column_cap = _cap("max_columns", max_columns, MAX_SCHEMA_COLUMNS, 1024, CODE["INVALID_SCHEMA"])
        clause_cap = _cap("max_clauses", max_clauses, MAX_ORDER_CLAUSES, 64, CODE["INVALID_SCHEMA"])
        if len(table_names) > table_cap:
            fail(CODE["INVALID_SCHEMA"], "schema table count exceeds max_tables (" + str(table_cap) + ")")
        normalized: Dict[str, _TableSpec] = {}
        seen_tables = set()
        for table_name in table_names:
            assert_identifier(table_name, "schema table")
            if table_name in seen_tables:
                fail(CODE["INVALID_SCHEMA"], "schema repeats table " + table_name)
            seen_tables.add(table_name)
            table_spec = _normalize_table_spec(table_name, schema[table_name])
            if len(table_spec.columns) > column_cap:
                fail(CODE["INVALID_SCHEMA"], "schema table " + table_name + " exceeds max_columns (" + str(column_cap) + ")")
            normalized[table_name] = table_spec
        limit_cap = None
        if max_limit is not None:
            if type(max_limit) is not int or max_limit < 1:
                fail(CODE["INVALID_SCHEMA"], "max_limit must be a positive integer")
            limit_cap = max_limit
        object.__setattr__(self, "_dialect", selected)
        object.__setattr__(self, "_tables", tuple(table_names))
        object.__setattr__(self, "_specs", MappingProxyType(normalized))
        object.__setattr__(self, "_max_columns", column_cap)
        object.__setattr__(self, "_max_clauses", clause_cap)
        object.__setattr__(self, "_max_limit", limit_cap)
        object.__setattr__(self, "_frozen", True)

    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_frozen", False):
            raise AttributeError("SchemaGuard is immutable")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        raise AttributeError("SchemaGuard is immutable")

    @property
    def dialect(self) -> str:
        return self._dialect

    @property
    def tables(self) -> Tuple[str, ...]:
        return self._tables

    def _table_spec(self, table: Any) -> _TableSpec:
        assert_identifier(table, "table")
        if table not in self._specs:
            fail(CODE["UNKNOWN_TABLE"], "table is not in the schema allowlist", {"table": table})
        return self._specs[table]

    def table(self, name: Any) -> Any:
        self._table_spec(name)
        return static_fragment(quote_identifier(name, self._dialect))

    def column(self, table: Any, column: Any) -> Any:
        spec = self._table_spec(table)
        assert_identifier(column, "column")
        if column not in spec.columns:
            fail(CODE["UNKNOWN_COLUMN"], "column is not in the table allowlist", {"table": table, "column": column})
        return static_fragment(qualified_identifier(column, self._dialect, table))

    def columns(self, table: Any, columns: Any) -> Any:
        spec = self._table_spec(table)
        return safe_columns(columns, spec.columns, dialect=self._dialect, table=table, max_columns=self._max_columns)

    def order_by(self, table: Any, clauses: Any) -> Any:
        spec = self._table_spec(table)
        return safe_order_by(clauses, spec.sortable, dialect=self._dialect, table=table, max_clauses=self._max_clauses)

    def limit_offset(self, limit: Any = None, offset: Any = 0, max_limit: Any = None) -> Any:
        if self._max_limit is None:
            effective = max_limit
        elif max_limit is None:
            effective = self._max_limit
        elif type(max_limit) is int and max_limit > 0:
            effective = min(self._max_limit, max_limit)
        else:
            effective = max_limit
        return safe_limit_offset(limit=limit, offset=offset, max_limit=effective)

    def set_clause(self, table: Any, patch: Any) -> Any:
        spec = self._table_spec(table)
        return sql_set(patch, dialect=self._dialect, allowed_columns=spec.columns, max_columns=self._max_columns)

    def values_clause(self, table: Any, rows: Any, columns: Any = None) -> Any:
        spec = self._table_spec(table)
        if columns is None:
            if type(rows) not in (list, tuple) or not rows or not isinstance(rows[0], Mapping):
                fail(CODE["EMPTY_VALUES"], "VALUES rows must be non-empty mappings when columns are not explicit")
            selected_columns = list(rows[0].keys())
        else:
            if type(columns) not in (list, tuple):
                fail(CODE["EMPTY_VALUES"], "VALUES columns must be a list or tuple")
            selected_columns = list(columns)
        if not selected_columns:
            fail(CODE["EMPTY_VALUES"], "VALUES columns must not be empty")
        for column in selected_columns:
            assert_identifier(column, "VALUES column")
            if column not in spec.columns:
                fail(CODE["UNKNOWN_COLUMN"], "VALUES column is not in the table allowlist", {"table": table, "column": column})
        return sql_values(rows, columns=selected_columns, max_parameters=1000)

    def has_table(self, name: Any) -> bool:
        return type(name) is str and name in self._specs

    def has_column(self, table: Any, column: Any) -> bool:
        return type(table) is str and type(column) is str and table in self._specs and column in self._specs[table].columns

    def columns_for(self, table: Any) -> Tuple[str, ...]:
        return self._table_spec(table).columns

    def sortable_for(self, table: Any) -> Tuple[str, ...]:
        return self._table_spec(table).sortable


def create_schema_guard(schema: Any, **options: Any) -> SchemaGuard:
    return SchemaGuard(schema, **options)
