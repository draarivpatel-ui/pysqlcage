from __future__ import annotations

import unittest

import pysqlcage as p
from pysqlcage import CODE, SqlCageError


def assert_code(test_case, key, function, *args, **kwargs):
    with test_case.assertRaises(SqlCageError) as caught:
        function(*args, **kwargs)
    test_case.assertEqual(caught.exception.code, CODE[key])
    return caught.exception


class ValidIdentifierMatrixTest(unittest.TestCase):
    pass


_VALID_IDENTIFIERS = [
    "a",
    "z",
    "A",
    "Z",
    "_",
    "_id",
    "id",
    "user_id",
    "UserID",
    "snake_case_name",
    "camelCase",
    "PascalCase",
    "a0",
    "z9",
    "A1",
    "_0",
    "x" * 63,
    "_" + "x" * 62,
]
_VALID_IDENTIFIERS += ["col_" + str(index) for index in range(80)]
_VALID_IDENTIFIERS += ["t" + format(index, "02x") for index in range(32)]


def _make_valid_identifier_case(name):
    def test(self):
        self.assertTrue(p.is_valid_identifier(name))
        self.assertEqual(p.assert_identifier(name), name)
    return test


for _index, _name in enumerate(_VALID_IDENTIFIERS):
    setattr(ValidIdentifierMatrixTest, "test_valid_%03d" % _index, _make_valid_identifier_case(_name))


class InvalidIdentifierMatrixTest(unittest.TestCase):
    pass


_INVALID_IDENTIFIERS = [
    "",
    "0abc",
    "1",
    "9" * 63,
    "x" * 64,
    "a b",
    "a-b",
    "a.b",
    "a$b",
    "a@b",
    "a#b",
    "a%b",
    "a&b",
    "a*b",
    "a+b",
    "a=b",
    "a/b",
    "a\\b",
    "a|b",
    "a,b",
    "a;b",
    "a:b",
    "a'b",
    'a"b',
    "a`b",
    "a(b)",
    "a[b]",
    "a{b}",
    "a<b>",
    "--",
    "id--",
    "/*x*/",
    "x/*",
    "x*/",
    "__proto__",
    "constructor",
    "prototype",
    "__PROTO__",
    "Constructor",
    "PROTOTYPE",
    "café",
    "αlpha",
    "\u0441bc",
    "ａbc",
    "user\u202e_id",
    "user\ufeffid",
    "üser",
    None,
    1,
    True,
    b"abc",
    ["abc"],
    {"x": 1},
]
_INVALID_IDENTIFIERS += ["bad" + chr(value) + "name" for value in range(1, 32)]
_INVALID_IDENTIFIERS += ["bad" + chr(127) + "name", "bad\x00name", "\x00abc", "abc\x00"]


def _make_invalid_identifier_case(value):
    def test(self):
        self.assertFalse(p.is_valid_identifier(value))
        assert_code(self, "INVALID_IDENTIFIER", p.assert_identifier, value)
    return test


for _index, _value in enumerate(_INVALID_IDENTIFIERS):
    setattr(InvalidIdentifierMatrixTest, "test_invalid_%03d" % _index, _make_invalid_identifier_case(_value))


class QuoteIdentifierTest(unittest.TestCase):
    def test_postgres_uses_double_quotes(self):
        self.assertEqual(p.quote_identifier("user_id", "postgres"), '"user_id"')

    def test_sqlite_uses_double_quotes(self):
        self.assertEqual(p.quote_identifier("user_id", "sqlite"), '"user_id"')

    def test_mysql_uses_backticks(self):
        self.assertEqual(p.quote_identifier("user_id", "mysql"), "`user_id`")

    def test_default_dialect_is_postgres(self):
        self.assertEqual(p.quote_identifier("user_id"), '"user_id"')

    def test_rejects_invalid_dialect(self):
        assert_code(self, "INVALID_DIALECT", p.quote_identifier, "user_id", "oracle")

    def test_rejects_nonstring_dialect(self):
        assert_code(self, "INVALID_DIALECT", p.quote_identifier, "user_id", 1)

    def test_rejects_empty_identifier_before_quoting(self):
        assert_code(self, "INVALID_IDENTIFIER", p.quote_identifier, "", "sqlite")

    def test_no_identifier_escape_is_needed_because_input_is_ascii_restricted(self):
        rendered = p.quote_identifier("abc", "postgres")
        self.assertNotIn('""', rendered[1:-1])
        self.assertEqual(len(rendered), 5)


class IdentifierBoundaryTest(unittest.TestCase):
    def test_length_one_is_valid(self):
        self.assertTrue(p.is_valid_identifier("x"))

    def test_length_63_is_valid(self):
        self.assertTrue(p.is_valid_identifier("x" * 63))

    def test_length_64_is_invalid(self):
        self.assertFalse(p.is_valid_identifier("x" * 64))

    def test_ascii_digits_are_allowed_after_first_character(self):
        self.assertTrue(p.is_valid_identifier("x0123456789"))

    def test_ascii_underscore_is_allowed_after_first_character(self):
        self.assertTrue(p.is_valid_identifier("x___"))

    def test_mixed_ascii_case_is_preserved(self):
        self.assertEqual(p.quote_identifier("AbC_123", "sqlite"), '"AbC_123"')

    def test_unicode_lookalike_is_rejected(self):
        assert_code(self, "INVALID_IDENTIFIER", p.quote_identifier, "\u0441sr", "sqlite")

    def test_null_byte_is_rejected(self):
        assert_code(self, "INVALID_IDENTIFIER", p.quote_identifier, "a\x00b", "sqlite")

    def test_comment_sequence_is_rejected(self):
        assert_code(self, "INVALID_IDENTIFIER", p.quote_identifier, "a--b", "sqlite")

    def test_semicolon_is_rejected(self):
        assert_code(self, "INVALID_IDENTIFIER", p.quote_identifier, "a;b", "sqlite")

    def test_space_is_rejected(self):
        assert_code(self, "INVALID_IDENTIFIER", p.quote_identifier, "a b", "sqlite")


if __name__ == "__main__":
    unittest.main()
