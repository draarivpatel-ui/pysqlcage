# pysqlcage

`pysqlcage` is a zero-dependency Python 3.9+ CWE-89 defense library. It builds parameterized SQL for PostgreSQL, MySQL, and SQLite without ever concatenating untrusted values into SQL text. It also provides strict schema allowlists, safe `IN`, `VALUES`, `SET`, `ORDER BY`, `LIMIT`, and `LIKE` helpers, plus a lexical SQL risk auditor and CLI.

## Install

The project is prepared for its first PyPI release. This README does not claim that the package has already been published. Until the release is live, install from a source checkout or wheel that you have verified:

```bash
python3 -m pip install .
```

After the first PyPI release, the intended command is:

```bash
python3 -m pip install pysqlcage
```

## Threat model

`pysqlcage` is designed to stop CWE-89 SQL injection caused by accidental string concatenation of attacker-controlled values. Its security boundary is explicit:

- SQL template text passed to `sql_fragment` is trusted developer input, just like source code.
- Values wrapped in `sql_param` are never interpolated into SQL text. They are returned separately in the driver parameter tuple.
- Naive and timezone-aware `datetime` values are both accepted and passed to the driver unchanged. Applications remain responsible for their own timezone policy.
- Table names, column names, ordering columns, and ordering directions cannot be parameterized by DB-API drivers. They are therefore validated against strict immutable allowlists.
- `SqlFragment` objects are immutable, exact-class, token-branded objects. JSON objects, dictionaries, strings, pickled copies, and subclass impostors are not accepted as trusted SQL fragments.
- The compiler fails closed with hard caps of 1000 parameters, 65536 SQL characters, and fragment nesting depth of 32.
- `audit_sql_query` is a defense-in-depth lexical reviewer for SQL text. It is not a proof that arbitrary SQL is safe, and it is not a replacement for parameter binding.

`pysqlcage` does not attempt to make handwritten raw SQL safe. It cannot validate application authorization, prevent unsafe database configuration, or protect a driver that itself mishandles parameters.

## Quick start

```python
from pysqlcage import SchemaGuard, compile_query, sql_fragment, sql_param

schema = SchemaGuard(
    {
        "users": {
            "columns": ["id", "email", "display_name", "created_at"],
            "sortable": ["id", "created_at"],
        }
    },
    dialect="sqlite",
)

user_email = "attacker@example.com' OR 1=1 --"
query = sql_fragment(
    "SELECT ", schema.columns("users", ["id", "email"]),
    " FROM ", schema.table("users"),
    " WHERE ", schema.column("users", "email"), " = ", sql_param(user_email),
    " ", schema.order_by("users", [("created_at", "DESC")]),
    " ", schema.limit_offset(limit=20, offset=0),
)

sql, params = compile_query(query, dialect="sqlite")
```

The compiled SQL contains placeholders. The attack string remains a parameter value:

```python
assert sql == (
    'SELECT "users"."id", "users"."email" FROM "users" WHERE '
    '"users"."email" = ? ORDER BY "users"."created_at" DESC LIMIT ? OFFSET ?'
)
assert params == (user_email, 20, 0)
```

## Real sqlite3 execution

The default SQLite paramstyle is `qmark`, so the result can be passed directly to the Python standard library driver:

```python
import sqlite3
from pysqlcage import compile_query, sql_fragment, sql_in, sql_param

connection = sqlite3.connect(":memory:")
connection.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
connection.executemany("INSERT INTO users (id, name) VALUES (?, ?)", [(1, "Ada"), (2, "Lin")])

payload = "1; DROP TABLE users;--"
query = sql_fragment(
    "SELECT name FROM users WHERE ",
    sql_in("id", [1, 2], dialect="sqlite"),
    " AND name <> ", sql_param(payload),
)
sql, params = compile_query(query, dialect="sqlite")
rows = connection.execute(sql, params).fetchall()
assert rows == [("Ada",), ("Lin",)]
connection.execute("SELECT COUNT(*) FROM users").fetchone()
```

## PostgreSQL and MySQL placeholder styles

PostgreSQL defaults to `%s`, which is compatible with psycopg:

```python
from pysqlcage import compile_query, sql_fragment, sql_param

query = sql_fragment("SELECT * FROM users WHERE id = ", sql_param(42))
assert compile_query(query, dialect="postgres") == (
    "SELECT * FROM users WHERE id = %s",
    (42,),
)
```

For asyncpg-style numeric placeholders, select `numeric`:

```python
assert compile_query(query, dialect="postgres", paramstyle="numeric") == (
    "SELECT * FROM users WHERE id = $1",
    (42,),
)
```

MySQL defaults to `%s`, and SQLite defaults to `?`. You can explicitly choose `qmark`, `format`, `pyformat`, or `numeric` where your driver requires one of those forms. In this library `format` and `pyformat` both emit `%s` because psycopg and common MySQL DB-API drivers accept that placeholder shape.

Compiled SQL is driver input, not final raw SQL. When `format` or `pyformat` is selected, every literal percent sign in trusted static template text is escaped as `%%` so a static `'%s'` string literal or a modulo operator cannot be mistaken for a generated placeholder. Generated parameter placeholders remain `%s`. `qmark` and `numeric` SQL text is not percent-escaped because those parameter styles do not use printf interpolation.

## Schema allowlists

`SchemaGuard` freezes a schema definition and rejects every unknown table, column, or sorting key:

```python
schema = SchemaGuard(
    {
        "users": {
            "columns": ["id", "email", "display_name"],
            "sortable": ["id"],
        }
    },
    dialect="postgres",
)

schema.table("users")
schema.column("users", "email")
schema.columns("users", ["id", "email"])
schema.order_by("users", [{"column": "id", "direction": "DESC"}])
schema.limit_offset(limit=50, offset=0)
schema.set_clause("users", {"display_name": "New name"})
schema.values_clause("users", [{"id": 7, "email": "a@example.com", "display_name": "Ada"}])
```

Unknown identifiers raise `SqlCageError` before any SQL reaches a database connection.

## IN, VALUES, SET, boolean, and LIKE helpers

```python
from pysqlcage import sql_and, sql_in, sql_like, sql_or, sql_param, sql_fragment, sql_set, sql_values

condition = sql_and([
    sql_fragment("age >= ", sql_param(18)),
    sql_in("id", [1, 2, 3]),
])

insert_values = sql_values([
    {"id": 1, "name": "Ada"},
    {"id": 2, "name": "Lin"},
])

update_set = sql_set({"name": "Ada"}, allowed_columns=["name"])

name_filter = sql_like("name", "100%_literal", dialect="postgres", mode="contains")
```

`sql_like` escapes `%`, `_`, and the selected escape character. MySQL defaults to `!` because backslash escaping changes meaning when `NO_BACKSLASH_ESCAPES` is enabled.

## SQL auditing CLI

Audit a file:

```bash
pysqlcage audit query.sql --dialect postgres --json
```

Audit standard input:

```bash
printf 'SELECT 1; DROP TABLE users\n' | python3 -m pysqlcage audit - --dialect sqlite
```

Exit status is `0` when no findings are present, `1` when the SQL is unsafe, and `2` for input or operational errors. File input is opened with symlink, file-type, race, size, encoding, and control-character defenses.

The MySQL lexer fails closed when a backslash immediately precedes a single or double quote because `NO_BACKSLASH_ESCAPES` changes where the string boundary lies. Such input is reported as `PYSQLCAGE_AMBIGUOUS_ESCAPE`. Backslashes never escape backtick-quoted MySQL identifiers.

## Python support and dependencies

- Python 3.9 through 3.13
- No runtime dependencies
- Typed package with `py.typed`
- Standard unittest test suite
- MIT license

## Development

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

The standard library test suite currently runs 893 tests.

Please read `CONTRIBUTING.md` before opening a pull request and `SECURITY.md` before reporting a vulnerability.
