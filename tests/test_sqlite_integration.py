from __future__ import annotations

import sqlite3
import unittest

import pysqlcage as p


SCHEMA = {
    "users": {
        "columns": ["id", "email", "display_name", "age", "created_at"],
        "sortable": ["id", "age", "created_at"],
    }
}


class SQLiteIntegrationBase(unittest.TestCase):
    def setUp(self):
        self.connection = sqlite3.connect(":memory:")
        self.connection.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, display_name TEXT, age INTEGER, created_at TEXT)"
        )
        self.connection.executemany(
            "INSERT INTO users (id, email, display_name, age, created_at) VALUES (?, ?, ?, ?, ?)",
            [
                (1, "ada@example.com", "Ada", 37, "2026-01-02"),
                (2, "lin@example.com", "Lin", 41, "2026-01-03"),
                (3, "grace@example.com", "Grace", 29, "2026-01-04"),
            ],
        )
        self.schema = p.SchemaGuard(SCHEMA, dialect="sqlite")

    def tearDown(self):
        self.connection.close()

    def execute_fragment(self, fragment):
        sql, params = p.compile_query(fragment, dialect="sqlite")
        return self.connection.execute(sql, params)


class SQLitePayloadMatrixTest(SQLiteIntegrationBase):
    pass


_PAYLOADS = [
    "' OR 1=1 --",
    "' OR '1'='1",
    "\" OR 1=1 --",
    "1; DROP TABLE users;--",
    "1; DROP TABLE users; --",
    "'; DROP TABLE users;--",
    "x' UNION SELECT password FROM users --",
    "%' OR 1=1 --",
    "admin'--",
    "admin' #",
    "admin'/*",
    "*/ DROP TABLE users --",
    "1) OR (1=1",
    "1')) OR ((1=1",
    "\\' OR 1=1 --",
    "x\x00' OR 1=1 --",
    "🔥' OR 1=1 --",
    "x\n'; DROP TABLE users;--",
    "x\r\n'; DELETE FROM users;--",
    "1;ATTACH DATABASE 'x' AS x;--",
    "1;SELECT load_extension('x')--",
    "x' OR id BETWEEN 1 AND 3 --",
    "x' OR age > 0 --",
    "x' OR display_name IS NOT NULL --",
    "x' OR 1=1 LIMIT 1 --",
    "x'; UPDATE users SET age=0;--",
    "x'; INSERT INTO users VALUES(9,'x','x',0,'x');--",
    "x'; DELETE FROM users;--",
    "x'; ALTER TABLE users ADD COLUMN x TEXT;--",
    "x'; CREATE TABLE x (id INTEGER);--",
]


def _make_payload_case(index, payload):
    def test(self):
        query = p.sql_fragment(
            "SELECT id FROM users WHERE email = ",
            p.sql_param(payload),
            " ORDER BY id ASC",
        )
        rows = self.execute_fragment(query).fetchall()
        self.assertEqual(rows, [])
        count = self.connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        self.assertEqual(count, 3)
    return test


for _index, _payload in enumerate(_PAYLOADS):
    setattr(SQLitePayloadMatrixTest, "test_payload_%02d" % _index, _make_payload_case(_index, _payload))


class SQLiteBuilderIntegrationTest(SQLiteIntegrationBase):
    def test_schema_select_order_limit_executes(self):
        query = p.sql_fragment(
            "SELECT ", self.schema.columns("users", ["id", "display_name"]),
            " FROM ", self.schema.table("users"),
            " ", self.schema.order_by("users", [("age", "DESC")]),
            " ", self.schema.limit_offset(2, 0),
        )
        rows = self.execute_fragment(query).fetchall()
        self.assertEqual(rows, [(2, "Lin"), (1, "Ada")])

    def test_order_offset_executes(self):
        query = p.sql_fragment(
            "SELECT id FROM ", self.schema.table("users"),
            " ", self.schema.order_by("users", ["id"]),
            " ", self.schema.limit_offset(2, 1),
        )
        rows = self.execute_fragment(query).fetchall()
        self.assertEqual(rows, [(2,), (3,)])

    def test_in_executes(self):
        query = p.sql_fragment(
            "SELECT id FROM users WHERE ",
            p.sql_in("id", [1, 3], dialect="sqlite"),
            " ORDER BY id ASC",
        )
        rows = self.execute_fragment(query).fetchall()
        self.assertEqual(rows, [(1,), (3,)])

    def test_in_payloads_are_bound(self):
        query = p.sql_fragment(
            "SELECT id FROM users WHERE ",
            p.sql_in("id", ["1) OR (1=1", "2;DROP TABLE users"], dialect="sqlite"),
        )
        rows = self.execute_fragment(query).fetchall()
        self.assertEqual(rows, [])
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM users").fetchone()[0], 3)

    def test_and_or_helpers_execute(self):
        condition = p.sql_and([
            p.sql_fragment("age >= ", p.sql_param(30)),
            p.sql_or([
                p.sql_fragment("id = ", p.sql_param(1)),
                p.sql_fragment("id = ", p.sql_param(2)),
            ]),
        ])
        query = p.sql_fragment("SELECT id FROM users WHERE ", condition, " ORDER BY id ASC")
        rows = self.execute_fragment(query).fetchall()
        self.assertEqual(rows, [(1,), (2,)])

    def test_like_exact_percent_executes_as_literal(self):
        self.connection.execute("INSERT INTO users VALUES (4, 'pct@example.com', '100% sure', 1, '2026-01-05')")
        query = p.sql_fragment("SELECT id FROM users WHERE ", p.sql_like("display_name", "100%", dialect="sqlite"))
        rows = self.execute_fragment(query).fetchall()
        self.assertEqual(rows, [(4,)])

    def test_like_underscore_is_literal(self):
        self.connection.execute("INSERT INTO users VALUES (4, 'u@example.com', 'a_c', 1, '2026-01-05')")
        self.connection.execute("INSERT INTO users VALUES (5, 'x@example.com', 'abc', 1, '2026-01-05')")
        query = p.sql_fragment("SELECT id FROM users WHERE ", p.sql_like("display_name", "a_c", dialect="sqlite"))
        rows = self.execute_fragment(query).fetchall()
        self.assertEqual(rows, [(4,)])

    def test_like_payload_cannot_union_select(self):
        query = p.sql_fragment(
            "SELECT id FROM users WHERE ",
            p.sql_like("display_name", "' UNION SELECT 1 --", dialect="sqlite"),
        )
        rows = self.execute_fragment(query).fetchall()
        self.assertEqual(rows, [])
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM users").fetchone()[0], 3)

    def test_values_insert_executes(self):
        values = self.schema.values_clause("users", [
            {"id": 4, "email": "n@example.com", "display_name": "N", "age": 20, "created_at": "2026-01-05"},
            {"id": 5, "email": "o@example.com", "display_name": "O", "age": 21, "created_at": "2026-01-06"},
        ])
        query = p.sql_fragment(
            "INSERT INTO ", self.schema.table("users"),
            " (id, email, display_name, age, created_at) ", values,
        )
        self.execute_fragment(query)
        count = self.connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        self.assertEqual(count, 5)

    def test_values_insert_payload_is_bound(self):
        payload = "x'); DROP TABLE users;--"
        values = self.schema.values_clause("users", [
            {"id": 4, "email": payload, "display_name": "N", "age": 20, "created_at": "2026-01-05"},
        ])
        query = p.sql_fragment(
            "INSERT INTO ", self.schema.table("users"),
            " (id, email, display_name, age, created_at) ", values,
        )
        self.execute_fragment(query)
        stored = self.connection.execute("SELECT email FROM users WHERE id = 4").fetchone()[0]
        self.assertEqual(stored, payload)
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM users").fetchone()[0], 4)

    def test_set_update_executes(self):
        patch = self.schema.set_clause("users", {"display_name": "Ada Lovelace", "age": 38})
        query = p.sql_fragment(
            "UPDATE ", self.schema.table("users"), " ", patch,
            " WHERE ", self.schema.column("users", "id"), " = ", p.sql_param(1),
        )
        self.execute_fragment(query)
        row = self.connection.execute("SELECT display_name, age FROM users WHERE id = 1").fetchone()
        self.assertEqual(row, ("Ada Lovelace", 38))

    def test_set_update_payload_is_bound(self):
        payload = "x', age=0 --"
        patch = self.schema.set_clause("users", {"display_name": payload})
        query = p.sql_fragment("UPDATE users ", patch, " WHERE id = ", p.sql_param(1))
        self.execute_fragment(query)
        row = self.connection.execute("SELECT display_name, age FROM users WHERE id = 1").fetchone()
        self.assertEqual(row, (payload, 37))

    def test_numeric_none_bool_bytes_and_uuid_like_text_are_driver_boundaries(self):
        query = p.sql_fragment(
            "SELECT ", p.sql_param(None), ", ", p.sql_param(True), ", ", p.sql_param(b"abc"), ", ", p.sql_param(12.5),
        )
        row = self.execute_fragment(query).fetchone()
        self.assertEqual(row[0], None)
        self.assertEqual(row[1], 1)
        self.assertEqual(row[2], b"abc")
        self.assertEqual(row[3], 12.5)

    def test_joined_fragment_query_executes(self):
        selected = p.sql_join([p.static_fragment("id"), p.static_fragment("display_name")], ", ")
        query = p.sql_fragment("SELECT ", selected, " FROM users ORDER BY id ASC LIMIT ", p.sql_param(1))
        rows = self.execute_fragment(query).fetchall()
        self.assertEqual(rows, [(1, "Ada")])

    def test_empty_in_false_predicate_executes(self):
        query = p.sql_fragment("SELECT id FROM users WHERE ", p.sql_in([], on_empty="false"))
        rows = self.execute_fragment(query).fetchall()
        self.assertEqual(rows, [])

    def test_zero_limit_is_rejected_before_execution(self):
        with self.assertRaises(p.SqlCageError):
            p.safe_limit_offset(0, 0)

    def test_nulls_last_executes_in_sqlite(self):
        self.connection.execute("INSERT INTO users VALUES (4, NULL, 'No mail', NULL, '2026-01-05')")
        query = p.sql_fragment(
            "SELECT id FROM users ",
            self.schema.order_by("users", [("age", "ASC", "LAST")]),
        )
        rows = self.execute_fragment(query).fetchall()
        self.assertEqual(rows[-1], (4,))


if __name__ == "__main__":
    unittest.main()
