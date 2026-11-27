from __future__ import annotations

import unittest

import pysqlcage as p
from pysqlcage import CODE, SqlCageError


def assert_code(test_case, key, function, *args, **kwargs):
    with test_case.assertRaises(SqlCageError) as caught:
        function(*args, **kwargs)
    test_case.assertEqual(caught.exception.code, CODE[key])
    return caught.exception


def finding_codes(result):
    return [finding.code for finding in result.findings]


def has_code(result, key):
    return CODE[key] in finding_codes(result)


class AuditApiTest(unittest.TestCase):
    def test_simple_select_is_safe(self):
        result = p.audit_sql_query("SELECT 1")
        self.assertTrue(result.safe)
        self.assertEqual(result.findings, ())
        self.assertEqual(result.stats.statements, 1)

    def test_attribute_and_mapping_access(self):
        result = p.audit_sql_query("SELECT 1; SELECT 2")
        self.assertFalse(result.safe)
        self.assertFalse(result["safe"])
        self.assertEqual(result["findings"], result.findings)
        self.assertEqual(result["stats"], result.stats)
        self.assertEqual(result.findings[0]["code"], result.findings[0].code)
        self.assertEqual(result.stats["statements"], 2)

    def test_to_dict_shape(self):
        result = p.audit_sql_query("SELECT 1; SELECT 2")
        data = result.to_dict()
        self.assertIn("safe", data)
        self.assertIn("findings", data)
        self.assertIn("stats", data)
        self.assertIsInstance(data["findings"], list)
        self.assertIsInstance(data["stats"], dict)

    def test_rejects_nonstring_input(self):
        assert_code(self, "INVALID_INPUT", p.audit_sql_query, b"SELECT 1")

    def test_rejects_invalid_dialect(self):
        assert_code(self, "INVALID_DIALECT", p.audit_sql_query, "SELECT 1", dialect="oracle")

    def test_rejects_invalid_max_length_type(self):
        assert_code(self, "INVALID_OPTIONS", p.audit_sql_query, "SELECT 1", max_sql_length=True)

    def test_rejects_zero_max_length(self):
        assert_code(self, "INVALID_OPTIONS", p.audit_sql_query, "SELECT 1", max_sql_length=0)

    def test_length_cap_generates_finding(self):
        result = p.audit_sql_query("SELECT 12345", max_sql_length=5)
        self.assertFalse(result.safe)
        self.assertTrue(has_code(result, "MAX_SQL_LENGTH"))

    def test_exact_length_cap_is_safe(self):
        result = p.audit_sql_query("SELECT", max_sql_length=6)
        self.assertTrue(result.safe)

    def test_nul_byte_generates_finding(self):
        result = p.audit_sql_query("SELECT \x00 1")
        self.assertFalse(result.safe)
        self.assertTrue(has_code(result, "NUL_BYTE"))
        self.assertEqual(result.stats.nul_bytes, 1)

    def test_multiple_nul_bytes_are_counted(self):
        result = p.audit_sql_query("\x00SELECT\x00 1\x00")
        self.assertEqual(result.stats.nul_bytes, 3)

    def test_trailing_semicolon_alone_is_not_stacked(self):
        result = p.audit_sql_query("SELECT 1;")
        self.assertTrue(result.safe)
        self.assertEqual(result.stats.semicolons, 1)
        self.assertEqual(result.stats.statements, 1)

    def test_empty_input_reports_zero_statements(self):
        result = p.audit_sql_query("")
        self.assertTrue(result.safe)
        self.assertEqual(result.stats.statements, 0)

    def test_whitespace_input_reports_zero_statements(self):
        result = p.audit_sql_query(" \t\r\n")
        self.assertTrue(result.safe)
        self.assertEqual(result.stats.statements, 0)


class AuditSafeLexingMatrixTest(unittest.TestCase):
    pass


def _make_safe_case(dialect, query):
    def test(self):
        result = p.audit_sql_query(query, dialect=dialect)
        self.assertTrue(result.safe, result.to_dict())
    return test


_SAFE_MATRIX = []
for _dialect in p.DIALECTS:
    _SAFE_MATRIX.extend([
        (_dialect, "SELECT 1"),
        (_dialect, "SELECT 'DROP TABLE users'"),
        (_dialect, "SELECT 'TRUNCATE x'"),
        (_dialect, "SELECT \"DROP\""),
        (_dialect, "SELECT `DROP`"),
        (_dialect, "SELECT ';'"),
        (_dialect, "SELECT '--'"),
        (_dialect, "SELECT '/*'"),
        (_dialect, "SELECT 1;"),
        (_dialect, "SELECT 1.5 + 2"),
    ])
for _index, (_dialect, _query) in enumerate(_SAFE_MATRIX):
    setattr(AuditSafeLexingMatrixTest, "test_safe_%03d" % _index, _make_safe_case(_dialect, _query))


class AuditDialectLexingTest(unittest.TestCase):
    def test_postgres_dollar_quoted_dangerous_text_is_not_live_sql(self):
        result = p.audit_sql_query("SELECT $$DROP TABLE users$$", dialect="postgres")
        self.assertTrue(result.safe)

    def test_postgres_tagged_dollar_quoted_text_is_not_live_sql(self):
        result = p.audit_sql_query("SELECT $tag$DROP TABLE users$tag$", dialect="postgres")
        self.assertTrue(result.safe)

    def test_mysql_does_not_treat_dollar_quote_as_string(self):
        result = p.audit_sql_query("SELECT $tag$DROP TABLE users$tag$", dialect="mysql")
        self.assertFalse(result.safe)
        self.assertTrue(has_code(result, "DANGEROUS_KEYWORD"))

    def test_sqlite_does_not_treat_dollar_quote_as_string(self):
        result = p.audit_sql_query("SELECT $tag$DROP TABLE users$tag$", dialect="sqlite")
        self.assertFalse(result.safe)
        self.assertTrue(has_code(result, "DANGEROUS_KEYWORD"))

    def test_postgres_escape_string_uses_backslash_escape(self):
        result = p.audit_sql_query("SELECT E'it\\'s fine'", dialect="postgres")
        self.assertTrue(result.safe)

    def test_postgres_escape_string_hides_dangerous_text(self):
        result = p.audit_sql_query("SELECT E'DROP\\' TABLE users'", dialect="postgres")
        self.assertTrue(result.safe)

    def test_postgres_standard_string_does_not_use_backslash_escape(self):
        result = p.audit_sql_query("SELECT 'x\\' DROP TABLE users", dialect="postgres")
        self.assertFalse(result.safe)
        self.assertTrue(has_code(result, "DANGEROUS_KEYWORD"))
        self.assertFalse(has_code(result, "UNBALANCED_QUOTE"))

    def test_mysql_backslash_quote_escape_is_mode_ambiguous(self):
        result = p.audit_sql_query("SELECT 'DROP\\' TABLE users'", dialect="mysql")
        self.assertFalse(result.safe)
        self.assertTrue(has_code(result, "AMBIGUOUS_ESCAPE"))

    def test_sqlite_string_does_not_use_backslash_escape(self):
        result = p.audit_sql_query("SELECT 'x\\' DROP TABLE users", dialect="sqlite")
        self.assertFalse(result.safe)
        self.assertTrue(has_code(result, "DANGEROUS_KEYWORD"))
        self.assertFalse(has_code(result, "UNBALANCED_QUOTE"))

    def test_doubled_single_quote_is_one_string(self):
        result = p.audit_sql_query("SELECT 'it''s fine'", dialect="sqlite")
        self.assertTrue(result.safe)

    def test_doubled_double_quote_is_one_identifier(self):
        result = p.audit_sql_query('SELECT "weird""name"', dialect="sqlite")
        self.assertTrue(result.safe)

    def test_postgres_nested_block_comment_is_lexed_nested(self):
        result = p.audit_sql_query("SELECT 1 /* outer /* inner */ still comment */", dialect="postgres")
        self.assertFalse(result.safe)
        self.assertTrue(has_code(result, "COMMENT_TOKEN"))
        self.assertFalse(has_code(result, "UNBALANCED_QUOTE"))

    def test_postgres_unclosed_nested_comment_is_unbalanced(self):
        result = p.audit_sql_query("SELECT 1 /* outer /* inner */", dialect="postgres")
        self.assertFalse(result.safe)
        self.assertTrue(has_code(result, "UNBALANCED_QUOTE"))

    def test_mysql_comments_are_not_nested(self):
        result = p.audit_sql_query("SELECT 1 /* outer /* inner */", dialect="mysql")
        self.assertFalse(result.safe)
        self.assertFalse(has_code(result, "UNBALANCED_QUOTE"))

    def test_mysql_executable_comment_is_scanned_as_live_sql(self):
        result = p.audit_sql_query("SELECT * FROM users WHERE id=1 /*!50000 DROP TABLE users */", dialect="mysql")
        self.assertFalse(result.safe)
        self.assertTrue(has_code(result, "COMMENT_TOKEN"))
        self.assertTrue(has_code(result, "DANGEROUS_KEYWORD"))

    def test_mysql_executable_comment_semicolon_is_live_sql(self):
        result = p.audit_sql_query("SELECT 1 /*!50000 ; SELECT 2 */", dialect="mysql")
        self.assertFalse(result.safe)
        self.assertTrue(has_code(result, "MULTI_STATEMENT"))

    def test_postgres_normal_block_comment_does_not_execute_drop(self):
        result = p.audit_sql_query("SELECT 1 /* DROP TABLE users */", dialect="postgres")
        self.assertFalse(result.safe)
        self.assertTrue(has_code(result, "COMMENT_TOKEN"))
        self.assertFalse(has_code(result, "DANGEROUS_KEYWORD"))

    def test_mysql_dash_requires_whitespace(self):
        result = p.audit_sql_query("SELECT 1--x", dialect="mysql")
        self.assertTrue(result.safe)

    def test_mysql_dash_space_is_comment(self):
        result = p.audit_sql_query("SELECT 1-- x", dialect="mysql")
        self.assertFalse(result.safe)
        self.assertTrue(has_code(result, "COMMENT_TOKEN"))

    def test_mysql_dash_at_end_is_comment(self):
        result = p.audit_sql_query("SELECT 1--", dialect="mysql")
        self.assertFalse(result.safe)
        self.assertTrue(has_code(result, "COMMENT_TOKEN"))

    def test_postgres_dash_without_space_is_comment(self):
        result = p.audit_sql_query("SELECT 1--x", dialect="postgres")
        self.assertFalse(result.safe)
        self.assertTrue(has_code(result, "COMMENT_TOKEN"))

    def test_sqlite_dash_without_space_is_comment(self):
        result = p.audit_sql_query("SELECT 1--x", dialect="sqlite")
        self.assertFalse(result.safe)
        self.assertTrue(has_code(result, "COMMENT_TOKEN"))

    def test_hash_comment_is_flagged(self):
        result = p.audit_sql_query("SELECT 1 # comment", dialect="mysql")
        self.assertFalse(result.safe)
        self.assertTrue(has_code(result, "COMMENT_TOKEN"))


class AuditDangerousKeywordMatrixTest(unittest.TestCase):
    pass


def _make_dangerous_case(dialect, keyword):
    def test(self):
        query = "SELECT 1; " + keyword + " TABLE users"
        result = p.audit_sql_query(query, dialect=dialect)
        self.assertFalse(result.safe)
        self.assertTrue(has_code(result, "DANGEROUS_KEYWORD"))
    return test


for _dialect in p.DIALECTS:
    for _keyword in ("DROP", "TRUNCATE", "ALTER", "GRANT", "REVOKE", "XP_CMDSHELL", "LOAD_FILE"):
        setattr(
            AuditDangerousKeywordMatrixTest,
            "test_" + _dialect + "_" + _keyword.lower(),
            _make_dangerous_case(_dialect, _keyword),
        )


class AuditCompoundKeywordTest(unittest.TestCase):
    def test_into_outfile(self):
        result = p.audit_sql_query("SELECT * INTO OUTFILE '/tmp/x' FROM users", dialect="mysql")
        self.assertTrue(has_code(result, "DANGEROUS_KEYWORD"))
        self.assertIn("INTO OUTFILE", [finding.token for finding in result.findings])

    def test_attach_database(self):
        result = p.audit_sql_query("ATTACH DATABASE 'x.db' AS x", dialect="sqlite")
        self.assertTrue(has_code(result, "DANGEROUS_KEYWORD"))

    def test_bulk_insert(self):
        result = p.audit_sql_query("BULK INSERT users FROM 'x.csv'", dialect="postgres")
        self.assertTrue(has_code(result, "DANGEROUS_KEYWORD"))

    def test_copy_program(self):
        result = p.audit_sql_query("COPY users FROM PROGRAM 'sh'", dialect="postgres")
        self.assertTrue(has_code(result, "DANGEROUS_KEYWORD"))

    def test_copy_without_program_is_not_dangerous_keyword(self):
        result = p.audit_sql_query("COPY users FROM STDIN", dialect="postgres")
        self.assertTrue(result.safe)

    def test_copy_program_in_second_statement_still_flags_multi_and_copy(self):
        result = p.audit_sql_query("COPY users FROM STDIN; SELECT PROGRAM", dialect="postgres")
        self.assertTrue(has_code(result, "MULTI_STATEMENT"))
        self.assertFalse(any(finding.token == "COPY PROGRAM" for finding in result.findings))

    def test_keywords_inside_standard_string_are_not_flagged(self):
        result = p.audit_sql_query("SELECT 'DROP TRUNCATE ALTER GRANT'", dialect="postgres")
        self.assertTrue(result.safe)

    def test_lowercase_keyword_is_flagged(self):
        result = p.audit_sql_query("drop table users", dialect="sqlite")
        self.assertTrue(has_code(result, "DANGEROUS_KEYWORD"))

    def test_mixed_case_keyword_is_flagged(self):
        result = p.audit_sql_query("DrOp table users", dialect="sqlite")
        self.assertTrue(has_code(result, "DANGEROUS_KEYWORD"))


class AuditInlineCommentSplitMatrixTest(unittest.TestCase):
    pass


def _make_split_case(prefix, suffix):
    def test(self):
        result = p.audit_sql_query("SELECT " + prefix + "/**/" + suffix + " TABLE users", dialect="sqlite")
        self.assertFalse(result.safe)
        self.assertTrue(has_code(result, "COMMENT_TOKEN"))
        self.assertTrue(any("comment-split dangerous keyword" in finding.message for finding in result.findings))
    return test


for _index, (_prefix, _suffix) in enumerate((("DR", "OP"), ("D", "ROP"), ("DRO", "P"), ("TRUNC", "ATE"), ("ALT", "ER"), ("GR", "ANT"))):
    setattr(AuditInlineCommentSplitMatrixTest, "test_split_%02d" % _index, _make_split_case(_prefix, _suffix))


class AuditMultiStatementMatrixTest(unittest.TestCase):
    pass


def _make_multi_case(query):
    def test(self):
        result = p.audit_sql_query(query, dialect="sqlite")
        self.assertFalse(result.safe)
        self.assertTrue(has_code(result, "MULTI_STATEMENT"))
    return test


_MULTI_STATEMENT_QUERIES = [
    "SELECT 1; SELECT 2",
    "SELECT 1;DROP TABLE users",
    "SELECT 1 ;\nSELECT 2",
    "SELECT 1;;SELECT 2",
    "SELECT 1; --comment\nSELECT 2",
    "SELECT 1; /*comment*/ SELECT 2",
    ";SELECT 1",
    " ; SELECT 1",
    "SELECT 1;\t0",
    "SELECT 1;\r\nSELECT 2",
]
for _index, _query in enumerate(_MULTI_STATEMENT_QUERIES):
    setattr(AuditMultiStatementMatrixTest, "test_multi_%02d" % _index, _make_multi_case(_query))


class AuditUnbalancedMatrixTest(unittest.TestCase):
    pass


def _make_unbalanced_case(dialect, query):
    def test(self):
        result = p.audit_sql_query(query, dialect=dialect)
        self.assertFalse(result.safe)
        self.assertTrue(has_code(result, "UNBALANCED_QUOTE"))
    return test


_UNBALANCED_CASES = []
for _dialect in p.DIALECTS:
    _UNBALANCED_CASES.extend([
        (_dialect, "SELECT 'unterminated"),
        (_dialect, "SELECT \"unterminated"),
        (_dialect, "SELECT `unterminated"),
        (_dialect, "SELECT 1 /* unterminated"),
    ])
_UNBALANCED_CASES.extend([
    ("postgres", "SELECT $$unterminated"),
    ("postgres", "SELECT $tag$unterminated"),
    ("postgres", "SELECT E'it\\'s unterminated"),
])
for _index, (_dialect, _query) in enumerate(_UNBALANCED_CASES):
    setattr(AuditUnbalancedMatrixTest, "test_unbalanced_%02d" % _index, _make_unbalanced_case(_dialect, _query))


class AuditCommentTest(unittest.TestCase):
    def test_line_comment_is_flagged(self):
        result = p.audit_sql_query("SELECT 1 -- hello", dialect="postgres")
        self.assertTrue(has_code(result, "COMMENT_TOKEN"))

    def test_block_comment_is_flagged(self):
        result = p.audit_sql_query("SELECT 1 /* hello */", dialect="postgres")
        self.assertTrue(has_code(result, "COMMENT_TOKEN"))
        self.assertEqual(result.stats.comments, 1)

    def test_semicolon_inside_line_comment_is_not_statement_separator(self):
        result = p.audit_sql_query("SELECT 1 -- ;\n", dialect="postgres")
        self.assertFalse(result.safe)
        self.assertFalse(has_code(result, "MULTI_STATEMENT"))
        self.assertEqual(result.stats.semicolons, 0)

    def test_semicolon_inside_block_comment_is_not_statement_separator(self):
        result = p.audit_sql_query("SELECT 1 /* ; */", dialect="postgres")
        self.assertFalse(result.safe)
        self.assertFalse(has_code(result, "MULTI_STATEMENT"))
        self.assertEqual(result.stats.semicolons, 0)

    def test_dangerous_keyword_inside_line_comment_is_not_live(self):
        result = p.audit_sql_query("SELECT 1 -- DROP TABLE users\n", dialect="postgres")
        self.assertTrue(has_code(result, "COMMENT_TOKEN"))
        self.assertFalse(has_code(result, "DANGEROUS_KEYWORD"))

    def test_dangerous_keyword_inside_block_comment_is_not_live(self):
        result = p.audit_sql_query("SELECT 1 /* DROP TABLE users */", dialect="sqlite")
        self.assertTrue(has_code(result, "COMMENT_TOKEN"))
        self.assertFalse(has_code(result, "DANGEROUS_KEYWORD"))

    def test_many_findings_are_capped(self):
        query = "SELECT 1" + ("/*x*/" * 300)
        result = p.audit_sql_query(query, dialect="postgres")
        self.assertEqual(len(result.findings), 256)
        self.assertGreater(result.stats.truncated_findings, 0)

    def test_utf8_byte_count_is_reported(self):
        result = p.audit_sql_query("SELECT 'é'")
        self.assertEqual(result.stats.length, len("SELECT 'é'"))
        self.assertEqual(result.stats.bytes, len("SELECT 'é'".encode("utf-8")))


if __name__ == "__main__":
    unittest.main()
