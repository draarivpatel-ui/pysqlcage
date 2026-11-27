from __future__ import annotations

import copy
import os
import subprocess
import sys
import time
import unittest
from datetime import datetime, timezone
from decimal import Decimal
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


class FragmentForgeryHardeningTest(unittest.TestCase):
    def test_copy_copy_is_not_trusted(self):
        fragment = p.sql_fragment("SELECT ", p.sql_param(1))
        cloned = copy.copy(fragment)
        self.assertFalse(p.is_sql_fragment(cloned))
        assert_code(self, "INVALID_FRAGMENT", p.compile_query, cloned, dialect="sqlite")

    def test_deepcopy_is_not_trusted(self):
        fragment = p.sql_fragment("SELECT ", p.sql_param(1))
        cloned = copy.deepcopy(fragment)
        self.assertFalse(p.is_sql_fragment(cloned))
        assert_code(self, "INVALID_FRAGMENT", p.compile_query, cloned, dialect="sqlite")

    def test_shared_empty_fragment_dag_does_not_expand_exponentially(self):
        fragment = p.static_fragment("")
        for _ in range(32):
            fragment = p.sql_fragment(fragment, fragment)
        self.assertEqual(p.compile_query(fragment, dialect="sqlite"), ("", ()))

    def test_shared_empty_fragment_dag_still_enforces_depth_cap(self):
        fragment = p.static_fragment("")
        for _ in range(33):
            fragment = p.sql_fragment(fragment, fragment)
        assert_code(self, "MAX_FRAGMENT_DEPTH", p.compile_query, fragment, dialect="sqlite")

    def test_shared_nonempty_fragment_dag_still_expands_in_order(self):
        fragment = p.static_fragment("x")
        for _ in range(3):
            fragment = p.sql_fragment(fragment, " ", fragment)
        self.assertEqual(p.compile_query(fragment, dialect="sqlite"), ("x x x x x x x x", ()))


class ParamstyleLiteralHardeningTest(unittest.TestCase):
    def test_format_static_percent_literals_are_escaped_for_driver_interpolation(self):
        fragment = p.sql_fragment("SELECT '%s' AS literal_text, ", p.sql_param(1), ", 10 % 3, ", p.sql_param(2))
        sql, params = p.compile_query(fragment, dialect="postgres", paramstyle="format")
        self.assertEqual(sql, "SELECT '%%s' AS literal_text, %s, 10 %% 3, %s")
        self.assertEqual(params, (1, 2))

    def test_pyformat_static_percent_literals_are_escaped_for_driver_interpolation(self):
        fragment = p.sql_fragment("SELECT 100 %s ", p.sql_param(1))
        self.assertEqual(
            p.compile_query(fragment, dialect="mysql", paramstyle="pyformat"),
            ("SELECT 100 %%s %s", (1,)),
        )

    def test_qmark_static_literals_are_not_rewritten(self):
        fragment = p.sql_fragment("SELECT '?' AS q, '%s' AS f, ", p.sql_param(1))
        self.assertEqual(
            p.compile_query(fragment, dialect="sqlite", paramstyle="qmark"),
            ("SELECT '?' AS q, '%s' AS f, ?", (1,)),
        )

    def test_numeric_static_literals_do_not_change_generated_numbering(self):
        fragment = p.sql_fragment("SELECT '$1' AS literal_text, ", p.sql_param("x"), ", ", p.sql_param("y"))
        self.assertEqual(
            p.compile_query(fragment, dialect="postgres", paramstyle="numeric"),
            ("SELECT '$1' AS literal_text, $1, $2", ("x", "y")),
        )


class ImmutableObjectHardeningTest(unittest.TestCase):
    def test_schema_guard_object_setattr_cannot_widen_allowlist(self):
        guard = p.SchemaGuard({"users": ["id"]})
        with self.assertRaises(AttributeError):
            object.__setattr__(guard, "_specs", {})
        self.assertEqual(guard.columns_for("users"), ("id",))
        self.assertFalse(guard.has_column("users", "injected"))

    def test_schema_guard_cannot_be_subclassed(self):
        with self.assertRaises(TypeError):
            class ForgedSchemaGuard(p.SchemaGuard):
                pass

    def test_sql_cage_object_setattr_cannot_widen_compiler_caps(self):
        cage = p.SqlCage("sqlite", max_parameters=1)
        with self.assertRaises(AttributeError):
            object.__setattr__(cage, "_settings", {})
        fragment = p.sql_fragment(p.sql_param(1), p.sql_param(2))
        assert_code(self, "MAX_PARAMETERS", cage.compile, fragment)

    def test_sql_cage_cannot_be_subclassed(self):
        with self.assertRaises(TypeError):
            class ForgedSqlCage(p.SqlCage):
                pass


class SchemaValuesHardeningTest(unittest.TestCase):
    def test_explicit_sequence_row_width_must_match_columns(self):
        guard = p.SchemaGuard({"users": ["id", "email"]})
        assert_code(self, "EMPTY_VALUES", guard.values_clause, "users", [[1]], columns=["id", "email"])

    def test_explicit_sequence_row_with_matching_width_is_accepted(self):
        guard = p.SchemaGuard({"users": ["id", "email"]})
        fragment = guard.values_clause("users", [(1, "a@example.com")], columns=["id", "email"])
        self.assertEqual(p.compile_query(fragment, dialect="sqlite"), ("VALUES (?, ?)", (1, "a@example.com")))


class ScalarPolicyHardeningTest(unittest.TestCase):
    def test_aware_datetime_is_accepted_as_a_driver_boundary_value(self):
        value = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        _sql, params = p.compile_query(p.sql_fragment(p.sql_param(value)), dialect="sqlite")
        self.assertEqual(params, (value,))

    def test_non_integer_numeric_lookalikes_are_rejected_for_pagination(self):
        for value in (-0.0, Decimal("1"), "١٠"):
            with self.subTest(value=value):
                assert_code(self, "INVALID_LIMIT_OFFSET", p.safe_limit_offset, value, 0)


class AuditLexerHardeningTest(unittest.TestCase):
    def test_mysql_backslash_does_not_escape_backtick_identifier_boundary(self):
        result = p.audit_sql_query("SELECT `x\\`; DROP TABLE users; --`", dialect="mysql")
        self.assertFalse(result.safe)
        self.assertTrue(has_code(result, "MULTI_STATEMENT"))
        self.assertTrue(any(finding.token == "DROP" for finding in result.findings))
        self.assertFalse(has_code(result, "AMBIGUOUS_ESCAPE"))

    def test_mysql_backslash_quote_escape_is_fail_closed_mode_ambiguity(self):
        result = p.audit_sql_query("SELECT 'x\\'; DROP TABLE users; --'", dialect="mysql")
        self.assertFalse(result.safe)
        self.assertTrue(has_code(result, "AMBIGUOUS_ESCAPE"))

    def test_mysql_doubled_quote_string_without_backslash_remains_safe(self):
        result = p.audit_sql_query("SELECT 'it''s fine'", dialect="mysql")
        self.assertTrue(result.safe)

    def test_comment_split_dangerous_keyword_still_maps_to_original_start(self):
        result = p.audit_sql_query("SELECT D/*a*/R/*b*/OP TABLE users", dialect="sqlite")
        split = [finding for finding in result.findings if "comment-split dangerous keyword" in finding.message]
        self.assertEqual(len(split), 1)
        self.assertEqual(split[0].token, "DROP")
        self.assertEqual(split[0].index, len("SELECT "))

    def test_copy_program_scan_remains_correct_with_many_copy_tokens(self):
        query = " ".join(["COPY"] * 4000) + " PROGRAM"
        start = time.monotonic()
        result = p.audit_sql_query(query, dialect="postgres")
        elapsed = time.monotonic() - start
        self.assertTrue(any(finding.token == "COPY PROGRAM" for finding in result.findings))
        self.assertLess(elapsed, 1.0)

    def test_large_nul_scan_reports_count_without_index_list(self):
        result = p.audit_sql_query("\x00" * 200000)
        self.assertEqual(result.stats.nul_bytes, 200000)
        self.assertTrue(has_code(result, "NUL_BYTE"))


class CliOutputHardeningTest(unittest.TestCase):
    def run_cli(self, args, input_bytes=b"SELECT 1"):
        return subprocess.run(
            [sys.executable, "-m", "pysqlcage"] + list(args),
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=ENV,
            timeout=10,
            check=False,
        )

    def test_unrecognized_argument_newline_is_neutralized(self):
        result = self.run_cli(["audit", "-", "--unexpected\nINJECTED"])
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"--unexpected\\nINJECTED", result.stderr)
        self.assertEqual(len(result.stderr.splitlines()), 2)

    def test_unrecognized_argument_ansi_escape_is_neutralized(self):
        result = self.run_cli(["audit", "-", "--unexpected\x1b[31m"])
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(b"\x1b", result.stderr)
        self.assertIn(b"\\x1b", result.stderr)

    def test_unrecognized_argument_bidi_control_is_neutralized(self):
        result = self.run_cli(["audit", "-", "--unexpected\u202e"])
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("\u202e".encode("utf-8"), result.stderr)
        self.assertIn(b"\\u202e", result.stderr)


if __name__ == "__main__":
    unittest.main()
