from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import pysqlcage as p
from pysqlcage import CODE, SqlCageError

REPO_ROOT = Path(__file__).resolve().parents[1]
ENV = dict(os.environ)
ENV["PYTHONPATH"] = str(REPO_ROOT / "src")


def assert_code(test_case, key, function, *args, **kwargs):
    with test_case.assertRaises(SqlCageError) as caught:
        function(*args, **kwargs)
    test_case.assertEqual(caught.exception.code, CODE[key])
    return caught.exception


def has_code(result, key):
    return CODE[key] in [finding.code for finding in result.findings]


class CompilerRegressionTest(unittest.TestCase):
    def test_compile_preserves_whitespace_and_punctuation_exactly(self):
        source = "  SELECT\t*\n    FROM users  --x"
        self.assertEqual(p.compile_query(p.sql_fragment(source), dialect="sqlite"), (source, ()))

    def test_nested_fragments_compile_depth_first_in_parameter_order(self):
        first = p.sql_fragment("a = ", p.sql_param(1))
        second = p.sql_fragment("b = ", p.sql_param(2))
        outer = p.sql_fragment("WHERE ", first, " AND ", second, " AND c = ", p.sql_param(3))
        self.assertEqual(p.compile_query(outer, dialect="sqlite"), ("WHERE a = ? AND b = ? AND c = ?", (1, 2, 3)))

    def test_same_nested_fragment_reuse_duplicates_parameters_deliberately(self):
        inner = p.sql_fragment("x = ", p.sql_param(9))
        outer = p.sql_fragment(inner, " OR ", inner)
        self.assertEqual(p.compile_query(outer, dialect="sqlite"), ("x = ? OR x = ?", (9, 9)))

    def test_repeated_compilation_does_not_mutate_fragment(self):
        fragment = p.sql_fragment("SELECT ", p.sql_param(1))
        before = (fragment.strings, fragment.values)
        first = p.compile_query(fragment, dialect="sqlite")
        second = p.compile_query(fragment, dialect="sqlite")
        self.assertEqual(first, second)
        self.assertEqual((fragment.strings, fragment.values), before)

    def test_numeric_placeholders_do_not_become_confused_after_parameter_nine(self):
        fragment = p.sql_fragment(*[part for index in range(12) for part in (p.sql_param(index), ", ")])
        sql, params = p.compile_query(fragment, dialect="postgres", paramstyle="numeric")
        self.assertEqual(sql, "$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, ")
        self.assertEqual(params, tuple(range(12)))

    def test_max_sql_length_counts_generated_placeholders(self):
        fragment = p.sql_fragment("abc", p.sql_param(1))
        assert_code(self, "MAX_SQL_LENGTH", p.compile_query, fragment, dialect="sqlite", max_sql_length=3)
        self.assertEqual(p.compile_query(fragment, dialect="sqlite", max_sql_length=4), ("abc?", (1,)))

    def test_custom_lower_fragment_depth_is_enforced(self):
        fragment = p.sql_fragment(p.sql_fragment(p.sql_fragment("x")))
        assert_code(self, "MAX_FRAGMENT_DEPTH", p.compile_query, fragment, dialect="sqlite", max_fragment_depth=1)
        one_deep = p.sql_fragment(p.sql_fragment("x"))
        self.assertEqual(p.compile_query(one_deep, dialect="sqlite", max_fragment_depth=1), ("x", ()))

    def test_cage_base_parameter_policy_is_inherited(self):
        cage = p.SqlCage("sqlite", max_parameters=1)
        fragment = p.sql_fragment(p.sql_param(1), p.sql_param(2))
        assert_code(self, "MAX_PARAMETERS", cage.compile, fragment)

    def test_cage_dialect_can_be_overridden_per_compile(self):
        cage = p.SqlCage("sqlite")
        self.assertEqual(cage.compile(p.sql_fragment(p.sql_param(1)), dialect="postgres"), ("%s", (1,)))

    def test_helpers_return_genuine_fragments(self):
        helpers = [
            p.sql_in([1]),
            p.sql_values([(1,)]),
            p.sql_set({"a": 1}),
            p.sql_and([p.static_fragment("1=1")]),
            p.sql_or([p.static_fragment("1=1")]),
            p.sql_join([p.static_fragment("a")]),
            p.sql_like("a", "x"),
            p.safe_order_by(["a"], ["a"]),
            p.safe_limit_offset(1),
        ]
        for fragment in helpers:
            self.assertTrue(p.is_sql_fragment(fragment))


class SchemaAndHelperRegressionTest(unittest.TestCase):
    def test_schema_explicit_empty_sortable_list_forbids_order_by(self):
        guard = p.SchemaGuard({"users": {"columns": ["id"], "sortable": []}})
        assert_code(self, "UNKNOWN_COLUMN", guard.order_by, "users", ["id"])

    def test_schema_result_cannot_be_used_to_mutate_normalized_schema(self):
        guard = p.SchemaGuard({"users": ["id"]})
        columns = guard.columns_for("users")
        self.assertIsInstance(columns, tuple)
        with self.assertRaises(AttributeError):
            columns.append("injected")

    def test_order_by_rejects_ambiguous_extra_string_segments(self):
        for text in ("id:asc:first:extra", "id::nulls-last", "id:asc:", "id:nulls-last"):
            with self.subTest(text=text):
                assert_code(self, "INVALID_ORDER_BY", p.safe_order_by, text, ["id"])

    def test_order_by_hostile_compact_text_fails_closed(self):
        assert_code(self, "INVALID_ORDER_BY", p.safe_order_by, "id:desc; DROP TABLE users", ["id"])
        assert_code(self, "INVALID_IDENTIFIER", p.safe_order_by, "id:asc,__proto__:asc", ["id"])

    def test_safe_columns_is_case_sensitive(self):
        assert_code(self, "UNKNOWN_COLUMN", p.safe_columns, ["ID"], ["id"])

    def test_schema_lookup_is_case_sensitive(self):
        guard = p.SchemaGuard({"users": ["id"]})
        assert_code(self, "UNKNOWN_TABLE", guard.table, "Users")
        assert_code(self, "UNKNOWN_COLUMN", guard.column, "users", "ID")

    def test_sql_in_parameter_order_remains_stable_when_nested(self):
        fragment = p.sql_fragment(
            "WHERE a = ", p.sql_param(0),
            " AND id ", p.sql_in([1, 2]),
            " AND z = ", p.sql_param(3),
        )
        self.assertEqual(
            p.compile_query(fragment, dialect="sqlite"),
            ("WHERE a = ? AND id IN (?, ?) AND z = ?", (0, 1, 2, 3)),
        )

    def test_sql_in_one_item_has_no_trailing_comma(self):
        self.assertEqual(p.compile_query(p.sql_in([1]), dialect="sqlite"), ("IN (?)", (1,)))

    def test_sql_values_rejects_explicit_columns_missing_from_rows(self):
        assert_code(self, "EMPTY_VALUES", p.sql_values, [{"id": 1}], columns=["id", "name"])

    def test_sql_set_preserves_insertion_order(self):
        fragment = p.sql_set({"zed": 1, "alpha": 2, "middle": 3}, dialect="sqlite")
        self.assertEqual(
            p.compile_query(fragment, dialect="sqlite"),
            ('SET "zed" = ?, "alpha" = ?, "middle" = ?', (1, 2, 3)),
        )

    def test_sql_like_empty_search_string_is_mode_controlled(self):
        self.assertEqual(p.compile_query(p.sql_like("name", "", mode="contains"), dialect="sqlite")[1], ("%%",))
        self.assertEqual(p.compile_query(p.sql_like("name", "", mode="starts_with"), dialect="sqlite")[1], ("%",))
        self.assertEqual(p.compile_query(p.sql_like("name", "", mode="ends_with"), dialect="sqlite")[1], ("%",))

    def test_sql_like_custom_escape_appears_once_in_output(self):
        sql, params = p.compile_query(p.sql_like("name", "a%b", escape_char="!", dialect="postgres"), dialect="postgres")
        self.assertEqual(sql, '"name" LIKE %s ESCAPE \'!\'')
        self.assertEqual(params, ("%a!%b%",))

    def test_broad_helper_composition_stays_within_depth_budget(self):
        conditions = [p.sql_fragment("c = ", p.sql_param(index)) for index in range(100)]
        fragment = p.sql_fragment("WHERE ", p.sql_join(conditions, " AND "))
        _sql, params = p.compile_query(fragment, dialect="sqlite")
        self.assertEqual(len(params), 100)


class AuditRedteamRegressionTest(unittest.TestCase):
    def test_postgres_escape_string_cannot_hide_stacked_dangerous_sql(self):
        result = p.audit_sql_query("SELECT E'\\''; DROP TABLE users; --'", dialect="postgres")
        self.assertTrue(has_code(result, "MULTI_STATEMENT"))
        self.assertTrue(has_code(result, "DANGEROUS_KEYWORD"))

    def test_postgres_escape_string_remains_closed_across_backslash_quote_pair(self):
        result = p.audit_sql_query("SELECT E'it\\'s -- fine'", dialect="postgres")
        self.assertTrue(result.safe)

    def test_mysql_block_comment_does_not_hide_sql_after_first_terminator(self):
        result = p.audit_sql_query("/* outer /* inner */ DROP TABLE users */", dialect="mysql")
        self.assertTrue(any(finding.token == "DROP" for finding in result.findings))

    def test_sqlite_block_comment_does_not_hide_sql_after_first_terminator(self):
        result = p.audit_sql_query("/* outer /* inner */ DROP TABLE users */", dialect="sqlite")
        self.assertTrue(any(finding.token == "DROP" for finding in result.findings))

    def test_postgres_block_comment_nesting_still_hides_commented_text(self):
        result = p.audit_sql_query("/* outer /* inner */ DROP TABLE users */", dialect="postgres")
        self.assertFalse(any(finding.token == "DROP" for finding in result.findings))
        self.assertTrue(has_code(result, "COMMENT_TOKEN"))

    def test_mysql_double_dash_without_whitespace_exposes_following_keyword(self):
        result = p.audit_sql_query("SELECT 1--x DROP TABLE users", dialect="mysql")
        self.assertFalse(has_code(result, "COMMENT_TOKEN"))
        self.assertTrue(any(finding.token == "DROP" for finding in result.findings))

    def test_postgres_dollar_positional_parameters_are_not_dollar_quotes(self):
        result = p.audit_sql_query("SELECT * FROM users WHERE id = $1 AND x = $22", dialect="postgres")
        self.assertTrue(result.safe)

    def test_dollar_quote_tags_cannot_start_with_digits(self):
        result = p.audit_sql_query("SELECT $1$ DROP TABLE x $1$", dialect="postgres")
        self.assertTrue(has_code(result, "DANGEROUS_KEYWORD"))

    def test_comment_only_sql_has_zero_executable_statements_but_is_unsafe(self):
        result = p.audit_sql_query("-- only a comment")
        self.assertFalse(result.safe)
        self.assertEqual(result.stats.statements, 0)

    def test_semicolon_before_comment_does_not_count_comment_as_executable_sql(self):
        result = p.audit_sql_query("; -- comment")
        self.assertEqual(result.stats.statements, 0)
        self.assertFalse(has_code(result, "MULTI_STATEMENT"))

    def test_crlf_is_whitespace_for_statement_scanning(self):
        result = p.audit_sql_query("SELECT 1;\r\nSELECT 2")
        self.assertTrue(has_code(result, "MULTI_STATEMENT"))
        self.assertEqual(result.stats.statements, 2)

    def test_line_comment_ends_at_crlf_boundary(self):
        result = p.audit_sql_query("SELECT 1 -- x\r\nFROM users")
        self.assertEqual(result.stats.statements, 1)

    def test_hash_operator_shape_is_intentionally_flagged_as_comment(self):
        result = p.audit_sql_query("SELECT data::text, meta #>> '{a}' FROM t")
        self.assertTrue(any(finding.token == "#" for finding in result.findings))

    def test_keyword_scanner_requires_word_boundaries(self):
        for query in ("SELECT droplet FROM x", "SELECT alteration FROM x", "SELECT granted FROM x"):
            with self.subTest(query=query):
                self.assertTrue(p.audit_sql_query(query).safe)

    def test_dangerous_keyword_after_leading_empty_statement(self):
        result = p.audit_sql_query("; DROP TABLE x")
        self.assertTrue(has_code(result, "MULTI_STATEMENT"))
        self.assertTrue(has_code(result, "DANGEROUS_KEYWORD"))

    def test_max_length_still_scans_enough_input_to_preserve_lexical_findings(self):
        result = p.audit_sql_query("SELECT 1; DROP " + "x" * 100, max_sql_length=10)
        self.assertTrue(has_code(result, "MAX_SQL_LENGTH"))
        self.assertTrue(has_code(result, "DANGEROUS_KEYWORD"))


class CliRegressionTest(unittest.TestCase):
    def run_cli(self, args, input_bytes=None):
        return subprocess.run(
            [sys.executable, "-m", "pysqlcage"] + list(args),
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=ENV,
            timeout=10,
            check=False,
        )

    def test_help_exits_zero(self):
        result = self.run_cli(["--help"])
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"audit", result.stdout)

    def test_audit_help_exits_zero(self):
        result = self.run_cli(["audit", "--help"])
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"--dialect", result.stdout)

    def test_dialect_option_is_accepted_before_input_path(self):
        result = self.run_cli(["audit", "--dialect", "sqlite", "-"], b"SELECT 1")
        self.assertEqual(result.returncode, 0)

    def test_human_output_does_not_print_raw_sql_content(self):
        payload = "SELECT 1; DROP TABLE very_secret_table_name"
        result = self.run_cli(["audit", "-"], payload.encode())
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(b"very_secret_table_name", result.stdout)
        self.assertNotIn(b"very_secret_table_name", result.stderr)

    def test_human_output_lists_one_line_per_finding_plus_summary(self):
        result = self.run_cli(["audit", "-"], b"SELECT 1; DROP TABLE users")
        lines = result.stdout.decode().splitlines()
        self.assertEqual(lines[0].startswith("unsafe: "), True)
        self.assertGreaterEqual(len(lines), 3)
        for line in lines[1:]:
            self.assertTrue(line.startswith("- PYSQLCAGE_"))

    def test_json_output_is_single_line(self):
        result = self.run_cli(["audit", "-", "--json"], b"SELECT 1")
        self.assertEqual(len(result.stdout.splitlines()), 1)
        json.loads(result.stdout.decode())


if __name__ == "__main__":
    unittest.main()
