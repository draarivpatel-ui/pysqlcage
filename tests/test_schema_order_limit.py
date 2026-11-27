from __future__ import annotations

import unittest

import pysqlcage as p
from pysqlcage import CODE, SqlCageError


def assert_code(test_case, key, function, *args, **kwargs):
    with test_case.assertRaises(SqlCageError) as caught:
        function(*args, **kwargs)
    test_case.assertEqual(caught.exception.code, CODE[key])
    return caught.exception


SCHEMA = {
    "users": {
        "columns": ["id", "email", "display_name", "created_at"],
        "sortable": ["id", "created_at"],
    },
    "posts": ["id", "user_id", "title", "published_at"],
}


class SchemaGuardConstructionTest(unittest.TestCase):
    def test_constructs_with_mapping_table_specs(self):
        guard = p.SchemaGuard(SCHEMA, dialect="sqlite")
        self.assertEqual(guard.tables, ("users", "posts"))
        self.assertEqual(guard.dialect, "sqlite")

    def test_constructs_with_column_list_spec(self):
        guard = p.SchemaGuard({"users": ["id", "email"]}, dialect="postgres")
        self.assertEqual(guard.columns_for("users"), ("id", "email"))

    def test_sortable_defaults_to_all_columns(self):
        guard = p.SchemaGuard({"users": ["id", "email"]})
        self.assertEqual(guard.sortable_for("users"), ("id", "email"))

    def test_sortable_columns_alias_is_accepted(self):
        guard = p.SchemaGuard({"users": {"columns": ["id", "email"], "sortable_columns": ["id"]}})
        self.assertEqual(guard.sortable_for("users"), ("id",))

    def test_tables_tuple_is_immutable_copy(self):
        source = {"users": ["id"]}
        guard = p.SchemaGuard(source)
        source["posts"] = ["id"]
        self.assertEqual(guard.tables, ("users",))

    def test_column_source_mutation_does_not_mutate_guard(self):
        columns = ["id"]
        guard = p.SchemaGuard({"users": columns})
        columns.append("injected")
        self.assertEqual(guard.columns_for("users"), ("id",))

    def test_guard_rejects_attribute_assignment(self):
        guard = p.SchemaGuard({"users": ["id"]})
        with self.assertRaises(AttributeError):
            guard.tables = ("posts",)

    def test_has_table_true_and_false(self):
        guard = p.SchemaGuard(SCHEMA)
        self.assertTrue(guard.has_table("users"))
        self.assertFalse(guard.has_table("missing"))

    def test_has_column_true_and_false(self):
        guard = p.SchemaGuard(SCHEMA)
        self.assertTrue(guard.has_column("users", "id"))
        self.assertFalse(guard.has_column("users", "missing"))
        self.assertFalse(guard.has_column("missing", "id"))

    def test_rejects_nonmapping_schema(self):
        assert_code(self, "INVALID_SCHEMA", p.SchemaGuard, ["users"])

    def test_rejects_empty_schema(self):
        assert_code(self, "INVALID_SCHEMA", p.SchemaGuard, {})

    def test_rejects_bad_table_identifier(self):
        assert_code(self, "INVALID_IDENTIFIER", p.SchemaGuard, {"users;DROP": ["id"]})

    def test_rejects_nonlist_table_spec(self):
        assert_code(self, "INVALID_SCHEMA", p.SchemaGuard, {"users": "id"})

    def test_rejects_empty_columns(self):
        assert_code(self, "INVALID_SCHEMA", p.SchemaGuard, {"users": []})

    def test_rejects_missing_columns_in_mapping_spec(self):
        assert_code(self, "INVALID_SCHEMA", p.SchemaGuard, {"users": {"sortable": ["id"]}})

    def test_rejects_duplicate_columns(self):
        assert_code(self, "INVALID_SCHEMA", p.SchemaGuard, {"users": ["id", "id"]})

    def test_rejects_bad_column_identifier(self):
        assert_code(self, "INVALID_IDENTIFIER", p.SchemaGuard, {"users": ["id;"]})

    def test_rejects_duplicate_sortable_columns(self):
        assert_code(self, "INVALID_SCHEMA", p.SchemaGuard, {"users": {"columns": ["id"], "sortable": ["id", "id"]}})

    def test_rejects_sortable_column_outside_columns(self):
        assert_code(self, "INVALID_SCHEMA", p.SchemaGuard, {"users": {"columns": ["id"], "sortable": ["email"]}})

    def test_rejects_nonsequence_sortable(self):
        assert_code(self, "INVALID_SCHEMA", p.SchemaGuard, {"users": {"columns": ["id"], "sortable": "id"}})

    def test_rejects_too_many_tables(self):
        schema = {"t" + str(index): ["id"] for index in range(257)}
        assert_code(self, "INVALID_SCHEMA", p.SchemaGuard, schema)

    def test_rejects_too_many_columns(self):
        assert_code(self, "INVALID_SCHEMA", p.SchemaGuard, {"users": ["c" + str(index) for index in range(257)]})

    def test_max_tables_can_be_lowered(self):
        assert_code(self, "INVALID_SCHEMA", p.SchemaGuard, {"a": ["id"], "b": ["id"]}, max_tables=1)

    def test_max_columns_can_be_lowered(self):
        assert_code(self, "INVALID_SCHEMA", p.SchemaGuard, {"users": ["id", "email"]}, max_columns=1)

    def test_rejects_invalid_max_tables_type(self):
        assert_code(self, "INVALID_SCHEMA", p.SchemaGuard, {"users": ["id"]}, max_tables=True)


class SchemaAccessorTest(unittest.TestCase):
    def setUp(self):
        self.guard = p.SchemaGuard(SCHEMA, dialect="sqlite")

    def compile(self, fragment):
        return p.compile_query(fragment, dialect="sqlite")

    def test_table_returns_quoted_fragment(self):
        self.assertEqual(self.compile(self.guard.table("users")), ('"users"', ()))

    def test_column_returns_qualified_fragment(self):
        self.assertEqual(self.compile(self.guard.column("users", "id")), ('"users"."id"', ()))

    def test_columns_returns_comma_list(self):
        self.assertEqual(
            self.compile(self.guard.columns("users", ["id", "email"])),
            ('"users"."id", "users"."email"', ()),
        )

    def test_columns_deduplicates_input(self):
        self.assertEqual(self.compile(self.guard.columns("users", ["id", "id"])), ('"users"."id"', ()))

    def test_columns_rejects_unknown_table(self):
        assert_code(self, "UNKNOWN_TABLE", self.guard.columns, "missing", ["id"])

    def test_column_rejects_unknown_table(self):
        assert_code(self, "UNKNOWN_TABLE", self.guard.column, "missing", "id")

    def test_table_rejects_unknown_table(self):
        assert_code(self, "UNKNOWN_TABLE", self.guard.table, "missing")

    def test_column_rejects_unknown_column(self):
        assert_code(self, "UNKNOWN_COLUMN", self.guard.column, "users", "password")

    def test_columns_rejects_unknown_column(self):
        assert_code(self, "UNKNOWN_COLUMN", self.guard.columns, "users", ["id", "password"])

    def test_columns_rejects_empty_input(self):
        assert_code(self, "EMPTY_COLUMN_LIST", self.guard.columns, "users", [])

    def test_columns_rejects_string_input(self):
        assert_code(self, "EMPTY_COLUMN_LIST", self.guard.columns, "users", "id")

    def test_mysql_quoting(self):
        guard = p.SchemaGuard({"users": ["id"]}, dialect="mysql")
        self.assertEqual(p.compile_query(guard.column("users", "id"), dialect="mysql"), ("`users`.`id`", ()))


class OrderByTest(unittest.TestCase):
    def compile(self, fragment, dialect="sqlite"):
        return p.compile_query(fragment, dialect=dialect)

    def test_tuple_clause(self):
        fragment = p.safe_order_by([("id", "DESC")], ["id"], dialect="sqlite")
        self.assertEqual(self.compile(fragment), ('ORDER BY "id" DESC', ()))

    def test_mapping_clause(self):
        fragment = p.safe_order_by([{"column": "id", "direction": "ASC"}], ["id"], dialect="sqlite")
        self.assertEqual(self.compile(fragment), ('ORDER BY "id" ASC', ()))

    def test_plain_column_defaults_to_asc(self):
        fragment = p.safe_order_by(["id"], ["id"], dialect="sqlite")
        self.assertEqual(self.compile(fragment), ('ORDER BY "id" ASC', ()))

    def test_string_clause_format(self):
        fragment = p.safe_order_by("id:desc", ["id"], dialect="sqlite")
        self.assertEqual(self.compile(fragment), ('ORDER BY "id" DESC', ()))

    def test_comma_separated_string_format(self):
        fragment = p.safe_order_by("id:desc, email:asc", ["id", "email"], dialect="sqlite")
        self.assertEqual(self.compile(fragment), ('ORDER BY "id" DESC, "email" ASC', ()))

    def test_nulls_first_postgres(self):
        fragment = p.safe_order_by([("id", "DESC", "FIRST")], ["id"], dialect="postgres")
        self.assertEqual(self.compile(fragment, "postgres"), ('ORDER BY "id" DESC NULLS FIRST', ()))

    def test_nulls_last_sqlite(self):
        fragment = p.safe_order_by([{"column": "id", "direction": "ASC", "nulls": "LAST"}], ["id"], dialect="sqlite")
        self.assertEqual(self.compile(fragment), ('ORDER BY "id" ASC NULLS LAST', ()))

    def test_nulls_string_format(self):
        fragment = p.safe_order_by("id:desc:nulls-last", ["id"], dialect="postgres")
        self.assertEqual(self.compile(fragment, "postgres"), ('ORDER BY "id" DESC NULLS LAST', ()))

    def test_mysql_rejects_nulls_first(self):
        assert_code(self, "INVALID_ORDER_BY", p.safe_order_by, [("id", "ASC", "FIRST")], ["id"], dialect="mysql")

    def test_table_qualification(self):
        fragment = p.safe_order_by(["id"], ["id"], table="users", dialect="sqlite")
        self.assertEqual(self.compile(fragment), ('ORDER BY "users"."id" ASC', ()))

    def test_rejects_unknown_sortable_column(self):
        assert_code(self, "UNKNOWN_COLUMN", p.safe_order_by, ["password"], ["id"])

    def test_rejects_duplicate_column(self):
        assert_code(self, "INVALID_ORDER_BY", p.safe_order_by, ["id", "id"], ["id"])

    def test_rejects_empty_clauses(self):
        assert_code(self, "EMPTY_ORDER_BY", p.safe_order_by, [], ["id"])

    def test_rejects_bad_direction(self):
        assert_code(self, "INVALID_ORDER_BY", p.safe_order_by, [("id", " sideways ")], ["id"])

    def test_rejects_nonstr_direction(self):
        assert_code(self, "INVALID_ORDER_BY", p.safe_order_by, [("id", 1)], ["id"])

    def test_rejects_bad_nulls(self):
        assert_code(self, "INVALID_ORDER_BY", p.safe_order_by, [("id", "ASC", "MIDDLE")], ["id"])

    def test_rejects_bad_column_identifier(self):
        assert_code(self, "INVALID_IDENTIFIER", p.safe_order_by, ["id;DROP"], ["id;DROP"])

    def test_rejects_too_many_clauses(self):
        clauses = [("c" + str(index), "ASC") for index in range(17)]
        allowed = ["c" + str(index) for index in range(17)]
        assert_code(self, "INVALID_ORDER_BY", p.safe_order_by, clauses, allowed)

    def test_schema_order_by_uses_sortable_allowlist(self):
        guard = p.SchemaGuard(SCHEMA, dialect="sqlite")
        fragment = guard.order_by("users", [("created_at", "DESC")])
        self.assertEqual(self.compile(fragment), ('ORDER BY "users"."created_at" DESC', ()))

    def test_schema_order_by_rejects_unsortable_column(self):
        guard = p.SchemaGuard(SCHEMA, dialect="sqlite")
        assert_code(self, "UNKNOWN_COLUMN", guard.order_by, "users", ["email"])


class LimitOffsetTest(unittest.TestCase):
    def test_compiles_parameterized_limit_and_offset(self):
        fragment = p.safe_limit_offset(limit=20, offset=40)
        self.assertEqual(p.compile_query(fragment, dialect="sqlite"), ("LIMIT ? OFFSET ?", (20, 40)))

    def test_zero_limit_is_rejected_as_a_nonpositive_page_size(self):
        assert_code(self, "INVALID_LIMIT_OFFSET", p.safe_limit_offset, 0, 0)

    def test_input_max_limit_can_exceed_default_policy(self):
        fragment = p.safe_limit_offset({"limit": 1500, "max_limit": 1500})
        self.assertEqual(p.compile_query(fragment, dialect="sqlite"), ("LIMIT ? OFFSET ?", (1500, 0)))

    def test_default_max_limit_rejects_1001(self):
        assert_code(self, "INVALID_LIMIT_OFFSET", p.safe_limit_offset, 1001, 0)

    def test_mapping_input_is_accepted(self):
        fragment = p.safe_limit_offset({"limit": 5, "offset": 2, "max_limit": 10})
        self.assertEqual(p.compile_query(fragment, dialect="sqlite"), ("LIMIT ? OFFSET ?", (5, 2)))

    def test_max_limit_is_enforced(self):
        assert_code(self, "INVALID_LIMIT_OFFSET", p.safe_limit_offset, 11, 0, 10)

    def test_schema_without_configured_cap_allows_caller_max_limit_override(self):
        guard = p.SchemaGuard({"users": ["id"]})
        fragment = guard.limit_offset(1500, 0, 1500)
        self.assertEqual(p.compile_query(fragment, dialect="sqlite"), ("LIMIT ? OFFSET ?", (1500, 0)))

    def test_schema_configured_max_limit_is_enforced(self):
        guard = p.SchemaGuard({"users": ["id"]}, max_limit=5)
        assert_code(self, "INVALID_LIMIT_OFFSET", guard.limit_offset, 6, 0)

    def test_schema_caller_max_limit_can_be_lowered(self):
        guard = p.SchemaGuard({"users": ["id"]}, max_limit=10)
        assert_code(self, "INVALID_LIMIT_OFFSET", guard.limit_offset, 6, 0, 5)

    def test_schema_limit_fragment_uses_parameters(self):
        guard = p.SchemaGuard({"users": ["id"]}, max_limit=10)
        self.assertEqual(p.compile_query(guard.limit_offset(4, 2), dialect="sqlite"), ("LIMIT ? OFFSET ?", (4, 2)))


class LimitOffsetInvalidMatrixTest(unittest.TestCase):
    pass


def _make_limit_case(label, args, kwargs):
    def test(self):
        assert_code(self, "INVALID_LIMIT_OFFSET", p.safe_limit_offset, *args, **kwargs)
    return test


_LIMIT_CASES = [
    ("bool_limit", (True,), {}),
    ("bool_offset", (1, True), {}),
    ("float_limit", (1.5,), {}),
    ("float_offset", (1, 0.0), {}),
    ("nan_limit", (float("nan"),), {}),
    ("negative_limit", (-1,), {}),
    ("negative_offset", (1, -1), {}),
    ("string_limit", ("1",), {}),
    ("string_offset", (1, "0"), {}),
    ("none_limit", (None,), {}),
    ("list_limit", ([],), {}),
    ("bool_max_limit", (1, 0, True), {}),
    ("zero_max_limit", (1, 0, 0), {}),
    ("negative_max_limit", (1, 0, -5), {}),
    ("float_max_limit", (1, 0, 2.0), {}),
    ("mapping_plus_offset", ({"limit": 1}, 1), {}),
]
for _label, _args, _kwargs in _LIMIT_CASES:
    setattr(LimitOffsetInvalidMatrixTest, "test_" + _label, _make_limit_case(_label, _args, _kwargs))


class SchemaSetAndValuesTest(unittest.TestCase):
    def setUp(self):
        self.guard = p.SchemaGuard(SCHEMA, dialect="sqlite")

    def compile(self, fragment):
        return p.compile_query(fragment, dialect="sqlite")

    def test_set_clause_compiles(self):
        fragment = self.guard.set_clause("users", {"display_name": "Ada", "email": "a@example.com"})
        self.assertEqual(
            self.compile(fragment),
            ('SET "display_name" = ?, "email" = ?', ("Ada", "a@example.com")),
        )

    def test_set_clause_rejects_unknown_column(self):
        assert_code(self, "UNKNOWN_COLUMN", self.guard.set_clause, "users", {"password": "x"})

    def test_set_clause_rejects_empty_patch(self):
        assert_code(self, "EMPTY_SET", self.guard.set_clause, "users", {})

    def test_values_clause_compiles_subset_of_schema_columns(self):
        fragment = self.guard.values_clause("users", [{"id": 1, "email": "a@example.com"}])
        self.assertEqual(self.compile(fragment), ("VALUES (?, ?)", (1, "a@example.com")))

    def test_values_clause_compiles_multiple_rows(self):
        fragment = self.guard.values_clause("users", [
            {"id": 1, "email": "a@example.com"},
            {"id": 2, "email": "b@example.com"},
        ])
        self.assertEqual(self.compile(fragment), ("VALUES (?, ?), (?, ?)", (1, "a@example.com", 2, "b@example.com")))

    def test_values_clause_rejects_unknown_key(self):
        assert_code(self, "UNKNOWN_COLUMN", self.guard.values_clause, "users", [{"id": 1, "password": "x"}])

    def test_values_clause_rejects_empty_rows(self):
        assert_code(self, "EMPTY_VALUES", self.guard.values_clause, "users", [])

    def test_values_clause_rejects_empty_mapping(self):
        assert_code(self, "EMPTY_VALUES", self.guard.values_clause, "users", [{}])

    def test_values_clause_rejects_mismatched_row_keys(self):
        rows = [{"id": 1, "email": "a"}, {"id": 2, "display_name": "b"}]
        assert_code(self, "EMPTY_VALUES", self.guard.values_clause, "users", rows)

    def test_values_clause_explicit_columns(self):
        fragment = self.guard.values_clause("users", [{"id": 1, "email": "a"}], columns=["id", "email"])
        self.assertEqual(self.compile(fragment), ("VALUES (?, ?)", (1, "a")))


if __name__ == "__main__":
    unittest.main()
