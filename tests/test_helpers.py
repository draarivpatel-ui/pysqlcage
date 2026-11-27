from __future__ import annotations

import unittest

import pysqlcage as p
from pysqlcage import CODE, SqlCageError


def assert_code(test_case, key, function, *args, **kwargs):
    with test_case.assertRaises(SqlCageError) as caught:
        function(*args, **kwargs)
    test_case.assertEqual(caught.exception.code, CODE[key])
    return caught.exception


def compile_sqlite(fragment):
    return p.compile_query(fragment, dialect="sqlite")


class SqlJoinTest(unittest.TestCase):
    def test_joins_fragments_with_comma(self):
        parts = [p.static_fragment("a"), p.static_fragment("b"), p.static_fragment("c")]
        self.assertEqual(compile_sqlite(p.sql_join(parts)), ("a, b, c", ()))

    def test_empty_join_returns_empty_fragment(self):
        self.assertEqual(compile_sqlite(p.sql_join([])), ("", ()))

    def test_join_preserves_parameter_order(self):
        parts = [p.sql_fragment(p.sql_param(1)), p.sql_fragment(p.sql_param(2))]
        self.assertEqual(compile_sqlite(p.sql_join(parts, " AND ")), ("? AND ?", (1, 2)))

    def test_join_rejects_nonsequence(self):
        assert_code(self, "INVALID_INPUT", p.sql_join, "x")

    def test_join_rejects_nonfragment_part(self):
        assert_code(self, "INVALID_FRAGMENT", p.sql_join, [p.static_fragment("a"), "DROP"])

    def test_sql_and_wraps_each_condition(self):
        parts = [p.sql_fragment("a = ", p.sql_param(1)), p.sql_fragment("b = ", p.sql_param(2))]
        self.assertEqual(compile_sqlite(p.sql_and(parts)), ("(a = ?) AND (b = ?)", (1, 2)))

    def test_sql_or_wraps_each_condition(self):
        parts = [p.sql_fragment("a = ", p.sql_param(1)), p.sql_fragment("b = ", p.sql_param(2))]
        self.assertEqual(compile_sqlite(p.sql_or(parts)), ("(a = ?) OR (b = ?)", (1, 2)))

    def test_sql_and_rejects_empty(self):
        assert_code(self, "EMPTY_CONDITION_LIST", p.sql_and, [])

    def test_sql_or_rejects_empty(self):
        assert_code(self, "EMPTY_CONDITION_LIST", p.sql_or, [])

    def test_sql_and_rejects_nonsequence(self):
        assert_code(self, "EMPTY_CONDITION_LIST", p.sql_and, "x")


class JoinSeparatorValidMatrixTest(unittest.TestCase):
    pass


def _make_join_valid_case(separator):
    def test(self):
        parts = [p.static_fragment("a"), p.static_fragment("b")]
        sql, _params = compile_sqlite(p.sql_join(parts, separator))
        self.assertEqual(sql, "a" + separator + "b")
    return test


for _index, _separator in enumerate((",", ", ", " , ", "  ,  ", " AND ", "  and  ", " OR ", "  or  ")):
    setattr(JoinSeparatorValidMatrixTest, "test_valid_%02d" % _index, _make_join_valid_case(_separator))


class JoinSeparatorInvalidMatrixTest(unittest.TestCase):
    pass


def _make_join_invalid_case(separator):
    def test(self):
        assert_code(self, "INVALID_JOIN_SEPARATOR", p.sql_join, [p.static_fragment("a")], separator)
    return test


_INVALID_SEPARATORS = [
    "",
    ";",
    "--",
    "/*",
    "*/",
    " UNION ",
    " XOR ",
    "AND",
    "OR",
    " AND",
    "AND ",
    " OR",
    "OR ",
    " , , ",
    "x" * 33,
    "\x00",
    " \x01 ",
    "\x7f",
    None,
    1,
    True,
    b", ",
]
for _index, _separator in enumerate(_INVALID_SEPARATORS):
    setattr(JoinSeparatorInvalidMatrixTest, "test_invalid_%02d" % _index, _make_join_invalid_case(_separator))


class SqlInTest(unittest.TestCase):
    def test_values_only_form_renders_in_list(self):
        fragment = p.sql_in([1, 2, 3])
        self.assertEqual(compile_sqlite(fragment), ("IN (?, ?, ?)", (1, 2, 3)))

    def test_column_form_renders_quoted_column(self):
        fragment = p.sql_in("id", [1, 2], dialect="sqlite")
        self.assertEqual(compile_sqlite(fragment), ('"id" IN (?, ?)', (1, 2)))

    def test_mysql_column_form_uses_backticks(self):
        fragment = p.sql_in("id", [1], dialect="mysql")
        self.assertEqual(p.compile_query(fragment, dialect="mysql"), ("`id` IN (%s)", (1,)))

    def test_column_fragment_is_accepted(self):
        guard = p.SchemaGuard({"users": ["id"]}, dialect="sqlite")
        fragment = p.sql_in(guard.column("users", "id"), [1], dialect="sqlite")
        self.assertEqual(compile_sqlite(fragment), ('"users"."id" IN (?)', (1,)))

    def test_empty_defaults_to_throw(self):
        assert_code(self, "EMPTY_IN_LIST", p.sql_in, [])

    def test_empty_false_renders_false_predicate(self):
        self.assertEqual(compile_sqlite(p.sql_in([], on_empty="false")), ("1 = 0", ()))

    def test_empty_false_with_column_renders_false_predicate(self):
        self.assertEqual(compile_sqlite(p.sql_in("id", [], on_empty="false")), ("1 = 0", ()))

    def test_rejects_invalid_on_empty(self):
        assert_code(self, "INVALID_OPTIONS", p.sql_in, [], on_empty="true")

    def test_rejects_nonsequence_values(self):
        assert_code(self, "INVALID_INPUT", p.sql_in, "1,2")

    def test_rejects_invalid_column_identifier(self):
        assert_code(self, "INVALID_IDENTIFIER", p.sql_in, "id;DROP", [1])

    def test_count_cap_is_enforced_before_building(self):
        assert_code(self, "MAX_PARAMETERS", p.sql_in, list(range(1001)))

    def test_exactly_1000_values_is_allowed(self):
        sql, params = compile_sqlite(p.sql_in(list(range(1000))))
        self.assertEqual(len(params), 1000)
        self.assertEqual(sql.count("?"), 1000)

    def test_lower_count_cap_is_enforced(self):
        assert_code(self, "MAX_PARAMETERS", p.sql_in, [1, 2], max_parameters=1)

    def test_injection_values_remain_parameters(self):
        payload = "1) OR (1=1"
        sql, params = compile_sqlite(p.sql_in("id", [payload]))
        self.assertNotIn(payload, sql)
        self.assertEqual(params, (payload,))


class SqlValuesTest(unittest.TestCase):
    def test_sequence_rows_compile(self):
        fragment = p.sql_values([(1, "a"), (2, "b")])
        self.assertEqual(compile_sqlite(fragment), ("VALUES (?, ?), (?, ?)", (1, "a", 2, "b")))

    def test_mapping_rows_compile_in_column_order(self):
        fragment = p.sql_values([{"id": 1, "name": "a"}, {"name": "b", "id": 2}])
        self.assertEqual(compile_sqlite(fragment), ("VALUES (?, ?), (?, ?)", (1, "a", 2, "b")))

    def test_explicit_column_order_controls_mapping_rows(self):
        fragment = p.sql_values([{"id": 1, "name": "a"}], columns=["name", "id"])
        self.assertEqual(compile_sqlite(fragment), ("VALUES (?, ?)", ("a", 1)))

    def test_rejects_empty_rows(self):
        assert_code(self, "EMPTY_VALUES", p.sql_values, [])

    def test_rejects_empty_sequence_row(self):
        assert_code(self, "EMPTY_VALUES", p.sql_values, [[]])

    def test_rejects_mismatched_sequence_width(self):
        assert_code(self, "EMPTY_VALUES", p.sql_values, [(1,), (1, 2)])

    def test_rejects_scalar_row(self):
        assert_code(self, "EMPTY_VALUES", p.sql_values, [1])

    def test_rejects_mismatched_mapping_keys(self):
        assert_code(self, "EMPTY_VALUES", p.sql_values, [{"a": 1}, {"b": 1}])

    def test_rejects_missing_mapping_key(self):
        assert_code(self, "EMPTY_VALUES", p.sql_values, [{"a": 1, "b": 2}, {"a": 3}])

    def test_rejects_extra_mapping_key(self):
        assert_code(self, "EMPTY_VALUES", p.sql_values, [{"a": 1}, {"a": 3, "b": 4}])

    def test_rejects_bad_explicit_column(self):
        assert_code(self, "INVALID_IDENTIFIER", p.sql_values, [{"a": 1}], columns=["a;DROP"])

    def test_rejects_duplicate_explicit_column(self):
        assert_code(self, "EMPTY_VALUES", p.sql_values, [{"a": 1}], columns=["a", "a"])

    def test_rejects_too_many_rows(self):
        assert_code(self, "EMPTY_VALUES", p.sql_values, [(index,) for index in range(1001)])

    def test_row_cap_can_be_lowered(self):
        assert_code(self, "EMPTY_VALUES", p.sql_values, [(1,), (2,)], max_rows=1)

    def test_parameter_cap_is_enforced_before_building(self):
        rows = [(index,) for index in range(1001)]
        assert_code(self, "MAX_PARAMETERS", p.sql_values, rows, max_rows=1001)

    def test_exactly_1000_parameters_is_allowed(self):
        sql, params = compile_sqlite(p.sql_values([(index,) for index in range(1000)]))
        self.assertEqual(len(params), 1000)
        self.assertEqual(sql.count("?"), 1000)


class SqlSetTest(unittest.TestCase):
    def test_set_compiles_assignments_in_insertion_order(self):
        fragment = p.sql_set({"name": "Ada", "age": 37}, dialect="sqlite")
        self.assertEqual(compile_sqlite(fragment), ('SET "name" = ?, "age" = ?', ("Ada", 37)))

    def test_mysql_quotes_set_columns(self):
        fragment = p.sql_set({"name": "Ada"}, dialect="mysql")
        self.assertEqual(p.compile_query(fragment, dialect="mysql"), ("SET `name` = %s", ("Ada",)))

    def test_rejects_empty_assignments(self):
        assert_code(self, "EMPTY_SET", p.sql_set, {})

    def test_rejects_nonmapping_assignments(self):
        assert_code(self, "EMPTY_SET", p.sql_set, [("name", "Ada")])

    def test_rejects_bad_column_identifier(self):
        assert_code(self, "INVALID_IDENTIFIER", p.sql_set, {"name;DROP": "x"})

    def test_allowlist_accepts_allowed_column(self):
        fragment = p.sql_set({"name": "Ada"}, allowed_columns=["name"], dialect="sqlite")
        self.assertEqual(compile_sqlite(fragment), ('SET "name" = ?', ("Ada",)))

    def test_allowlist_rejects_unknown_column(self):
        assert_code(self, "UNKNOWN_COLUMN", p.sql_set, {"password": "x"}, allowed_columns=["name"])

    def test_rejects_too_many_columns(self):
        assignments = {"c" + str(index): index for index in range(129)}
        assert_code(self, "EMPTY_SET", p.sql_set, assignments)


class LikeEscapeTest(unittest.TestCase):
    def test_escapes_percent_underscore_and_escape_char(self):
        escaped = p.escape_like_pattern("100%_\\", "\\")
        self.assertEqual(escaped.pattern, "100" + "\\%" + "\\_" + "\\\\")
        self.assertEqual(escaped.escape_char, "\\")

    def test_bang_escape(self):
        escaped = p.escape_like_pattern("100%_!", "!")
        self.assertEqual(escaped.pattern, "100!%!_!!")

    def test_result_is_tuple_like_and_immutable(self):
        escaped = p.escape_like_pattern("x", "!")
        self.assertEqual(tuple(escaped), ("x", "!"))
        with self.assertRaises(AttributeError):
            escaped.pattern = "y"

    def test_rejects_nonstring_input(self):
        assert_code(self, "INVALID_LIKE_PATTERN", p.escape_like_pattern, b"x")

    def test_rejects_invalid_escape_character(self):
        assert_code(self, "INVALID_LIKE_PATTERN", p.escape_like_pattern, "x", "'")


class LikeEscapeMatrixTest(unittest.TestCase):
    pass


def _make_like_escape_case(escape, text):
    def test(self):
        escaped = p.escape_like_pattern(text, escape)
        self.assertEqual(escaped.escape_char, escape)
        for character in text:
            if character in ("%", "_", escape):
                self.assertIn(escape + character, escaped.pattern)
    return test


for _escape in ("\\", "!", "@", "#", "^", "~", "|"):
    for _index, _text in enumerate(("%", "_", _escape, "abc", "a%b_c" + _escape)):
        setattr(
            LikeEscapeMatrixTest,
            "test_escape_" + str({"\\": 0, "!": 1, "@": 2, "#": 3, "^": 4, "~": 5, "|": 6}[_escape]) + "_" + str(_index),
            _make_like_escape_case(_escape, _text),
        )


class SqlLikeTest(unittest.TestCase):
    def test_contains_mode_postgres(self):
        fragment = p.sql_like("name", "100%", dialect="postgres")
        sql, params = p.compile_query(fragment, dialect="postgres")
        self.assertEqual(sql, '"name" LIKE %s ESCAPE \'\\\'')
        self.assertEqual(params, ("%100\\%%",))

    def test_starts_with_mode(self):
        fragment = p.sql_like("name", "abc", dialect="sqlite", mode="starts_with")
        self.assertEqual(compile_sqlite(fragment)[1], ("abc%",))

    def test_ends_with_mode(self):
        fragment = p.sql_like("name", "abc", dialect="sqlite", mode="ends_with")
        self.assertEqual(compile_sqlite(fragment)[1], ("%abc",))

    def test_camel_case_mode_alias(self):
        fragment = p.sql_like("name", "abc", dialect="sqlite", mode="startsWith")
        self.assertEqual(compile_sqlite(fragment)[1], ("abc%",))

    def test_mysql_defaults_to_bang_escape(self):
        fragment = p.sql_like("name", "100%", dialect="mysql")
        sql, params = p.compile_query(fragment, dialect="mysql")
        self.assertEqual(sql, "`name` LIKE %s ESCAPE '!'")
        self.assertEqual(params, ("%100!%%",))

    def test_mysql_rejects_backslash_escape(self):
        assert_code(self, "INVALID_LIKE_PATTERN", p.sql_like, "name", "x", dialect="mysql", escape_char="\\")

    def test_schema_column_fragment_is_accepted(self):
        guard = p.SchemaGuard({"users": ["name"]}, dialect="sqlite")
        fragment = p.sql_like(guard.column("users", "name"), "x", dialect="sqlite")
        self.assertEqual(compile_sqlite(fragment)[0], '"users"."name" LIKE ? ESCAPE \'\\\'')

    def test_rejects_nonstring_value(self):
        assert_code(self, "INVALID_LIKE_PATTERN", p.sql_like, "name", 1)

    def test_rejects_bad_mode(self):
        assert_code(self, "INVALID_LIKE_PATTERN", p.sql_like, "name", "x", mode="regex")

    def test_rejects_too_long_pattern(self):
        assert_code(self, "INVALID_LIKE_PATTERN", p.sql_like, "name", "x" * 1025)

    def test_custom_max_pattern_length(self):
        assert_code(self, "INVALID_LIKE_PATTERN", p.sql_like, "name", "xx", max_pattern_length=1)

    def test_rejects_invalid_column(self):
        assert_code(self, "INVALID_IDENTIFIER", p.sql_like, "name;DROP", "x")


if __name__ == "__main__":
    unittest.main()
