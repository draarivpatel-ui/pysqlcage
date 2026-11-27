from __future__ import annotations

from .audit import AuditFinding, AuditResult, AuditStats, audit_sql_query
from .compiler import SqlCage, compile_query, create_sql_cage, validate_parameter
from .constants import CODE, DIALECTS, PARAMSTYLES, PYSQLCAGE_VERSION, SQLCAGE_VERSION
from .errors import SqlCageError
from .fragments import SqlFragment, SqlParam, is_sql_fragment, sql, sql_fragment, sql_param, static_fragment
from .helpers import (
    EscapedLikePattern,
    escape_like_pattern,
    safe_columns,
    safe_limit_offset,
    safe_order_by,
    sql_and,
    sql_in,
    sql_join,
    sql_like,
    sql_or,
    sql_set,
    sql_values,
    validate_join_separator,
)
from .identifiers import assert_identifier, is_valid_identifier, quote_identifier
from .schema import SchemaGuard, create_schema_guard

__version__ = PYSQLCAGE_VERSION

__all__ = [
    "AuditFinding",
    "AuditResult",
    "AuditStats",
    "CODE",
    "DIALECTS",
    "PARAMSTYLES",
    "PYSQLCAGE_VERSION",
    "SQLCAGE_VERSION",
    "SchemaGuard",
    "SqlCage",
    "SqlCageError",
    "SqlFragment",
    "SqlParam",
    "EscapedLikePattern",
    "__version__",
    "assert_identifier",
    "audit_sql_query",
    "compile_query",
    "create_schema_guard",
    "create_sql_cage",
    "escape_like_pattern",
    "is_sql_fragment",
    "is_valid_identifier",
    "quote_identifier",
    "safe_columns",
    "safe_limit_offset",
    "safe_order_by",
    "sql",
    "sql_and",
    "sql_fragment",
    "sql_in",
    "sql_join",
    "sql_like",
    "sql_or",
    "sql_param",
    "sql_set",
    "sql_values",
    "static_fragment",
    "validate_join_separator",
    "validate_parameter",
]
