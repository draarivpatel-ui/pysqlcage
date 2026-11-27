from __future__ import annotations

import math
import pickle
import unittest
from datetime import date, datetime
from decimal import Decimal
from uuid import UUID

import pysqlcage as p
from pysqlcage import CODE, SqlCageError


def assert_code(test_case, key, function, *args, **kwargs):
    with test_case.assertRaises(SqlCageError) as caught:
        function(*args, **kwargs)
    test_case.assertEqual(caught.exception.code, CODE[key])
    return caught.exception


class FragmentBrandingTest(unittest.TestCase):
    def test_empty_fragment_compiles_to_empty_sql(self):
        self.assertEqual(p.compile_query(p.sql_fragment(), dialect="sqlite"), ("", ()))

    def test_static_only_fragment_compiles(self):
        fragment = p.sql_fragment("SELECT ", "1")
        self.assertEqual(p.compile_query(fragment, dialect="sqlite"), ("SELECT 1", ()))

    def test_dynamic_parameter_is_bound_not_interpolated(self):
        payload = "' OR 1=1 --"
        fragment = p.sql_fragment("SELECT * FROM users WHERE name = ", p.sql_param(payload))
        self.assertEqual(p.compile_query(fragment, dialect="sqlite"), ("SELECT * FROM users WHERE name = ?", (payload,)))

    def test_adjacent_strings_are_concatenated_as_template_text(self):
        fragment = p.sql_fragment("SELECT ", "*", " FROM users")
        self.assertEqual(p.compile_query(fragment, dialect="sqlite"), ("SELECT * FROM users", ()))

    def test_nested_fragment_is_inlined_iteratively(self):
        inner = p.sql_fragment("id = ", p.sql_param(7))
        outer = p.sql_fragment("SELECT * FROM users WHERE ", inner, " AND active = ", p.sql_param(True))
        self.assertEqual(
            p.compile_query(outer, dialect="sqlite"),
            ("SELECT * FROM users WHERE id = ? AND active = ?", (7, True)),
        )

    def test_fragment_properties_are_tuples(self):
        fragment = p.sql_fragment("a", p.sql_param(1), "b")
        self.assertIsInstance(fragment.strings, tuple)
        self.assertIsInstance(fragment.values, tuple)
        self.assertEqual(fragment.strings, ("a", "b"))
        self.assertEqual(fragment.values, (1,))

    def test_repr_does_not_expose_parameter_values(self):
        fragment = p.sql_fragment("x", p.sql_param("secret"))
        rendered = repr(fragment)
        self.assertNotIn("secret", rendered)
        self.assertIn("SqlFragment", rendered)

    def test_fragment_rejects_attribute_assignment(self):
        fragment = p.sql_fragment("SELECT 1")
        with self.assertRaises(AttributeError):
            fragment.injected = "DROP TABLE users"

    def test_fragment_rejects_attribute_deletion(self):
        fragment = p.sql_fragment("SELECT 1")
        with self.assertRaises(AttributeError):
            del fragment.strings

    def test_fragment_constructor_requires_private_token(self):
        assert_code(self, "INVALID_FRAGMENT", p.SqlFragment, ("SELECT 1",), ())

    def test_fragment_cannot_be_subclassed(self):
        with self.assertRaises(TypeError):
            class ForgedFragment(p.SqlFragment):
                pass

    def test_param_cannot_be_subclassed(self):
        with self.assertRaises(TypeError):
            class ForgedParam(p.SqlParam):
                pass

    def test_param_constructor_requires_private_token(self):
        assert_code(self, "INVALID_PARAMETER", p.SqlParam, 1)

    def test_dict_is_not_a_fragment(self):
        self.assertFalse(p.is_sql_fragment({"strings": ["SELECT 1"], "values": []}))
        assert_code(self, "INVALID_FRAGMENT", p.compile_query, {"sql": "SELECT 1"}, dialect="sqlite")

    def test_string_is_not_a_fragment(self):
        self.assertFalse(p.is_sql_fragment("SELECT 1"))
        assert_code(self, "INVALID_FRAGMENT", p.compile_query, "SELECT 1", dialect="sqlite")

    def test_pickle_copy_is_not_trusted_even_if_pickle_succeeds(self):
        fragment = p.sql_fragment("SELECT 1")
        try:
            copied = pickle.loads(pickle.dumps(fragment))
        except Exception:
            return
        self.assertFalse(p.is_sql_fragment(copied))
        assert_code(self, "INVALID_FRAGMENT", p.compile_query, copied, dialect="sqlite")

    def test_object_setattr_cannot_mutate_fragment_data(self):
        fragment = p.sql_fragment("SELECT ", p.sql_param(1))
        with self.assertRaises(AttributeError):
            object.__setattr__(fragment, "_values", ("injected",))
        self.assertEqual(fragment.values, (1,))

    def test_object_new_without_brand_is_not_fragment(self):
        forged = object.__new__(p.SqlFragment)
        self.assertFalse(p.is_sql_fragment(forged))
        assert_code(self, "INVALID_FRAGMENT", p.compile_query, forged, dialect="sqlite")

    def test_fragment_rejects_unwrapped_dynamic_value(self):
        assert_code(self, "INVALID_FRAGMENT", p.sql_fragment, "SELECT ", 1)

    def test_fragment_rejects_none_part(self):
        assert_code(self, "INVALID_FRAGMENT", p.sql_fragment, "SELECT ", None)

    def test_fragment_rejects_dict_part(self):
        assert_code(self, "INVALID_FRAGMENT", p.sql_fragment, "SELECT ", {})

    def test_fragment_rejects_list_part(self):
        assert_code(self, "INVALID_FRAGMENT", p.sql_fragment, "SELECT ", [])

    def test_fragment_rejects_bytes_part(self):
        assert_code(self, "INVALID_FRAGMENT", p.sql_fragment, b"SELECT 1")

    def test_static_fragment_requires_exact_string(self):
        assert_code(self, "INVALID_FRAGMENT", p.static_fragment, "SELECT 1".encode())

    def test_sql_alias_is_sql_fragment(self):
        self.assertIs(p.sql, p.sql_fragment)


class CompilePlaceholderMatrixTest(unittest.TestCase):
    pass


def _make_compile_style_case(dialect, paramstyle, expected_marker):
    def test(self):
        fragment = p.sql_fragment("a=", p.sql_param(1), " AND b=", p.sql_param(2))
        sql, params = p.compile_query(fragment, dialect=dialect, paramstyle=paramstyle)
        if paramstyle == "numeric":
            expected = "a=$1 AND b=$2"
        elif paramstyle == "qmark":
            expected = "a=? AND b=?"
        else:
            expected = "a=%s AND b=%s"
        self.assertEqual(expected_marker, expected_marker)
        self.assertEqual(sql, expected)
        self.assertEqual(params, (1, 2))
    return test


for _dialect in p.DIALECTS:
    for _paramstyle in p.PARAMSTYLES:
        _expected = _paramstyle
        setattr(
            CompilePlaceholderMatrixTest,
            "test_" + _dialect + "_" + _paramstyle,
            _make_compile_style_case(_dialect, _paramstyle, _expected),
        )


class CompileDefaultsTest(unittest.TestCase):
    def test_postgres_default_is_percent_s(self):
        fragment = p.sql_fragment("SELECT ", p.sql_param(1))
        self.assertEqual(p.compile_query(fragment, dialect="postgres"), ("SELECT %s", (1,)))

    def test_mysql_default_is_percent_s(self):
        fragment = p.sql_fragment("SELECT ", p.sql_param(1))
        self.assertEqual(p.compile_query(fragment, dialect="mysql"), ("SELECT %s", (1,)))

    def test_sqlite_default_is_qmark(self):
        fragment = p.sql_fragment("SELECT ", p.sql_param(1))
        self.assertEqual(p.compile_query(fragment, dialect="sqlite"), ("SELECT ?", (1,)))

    def test_numeric_positions_are_one_based(self):
        fragment = p.sql_fragment(p.sql_param("a"), ",", p.sql_param("b"), ",", p.sql_param("c"))
        self.assertEqual(p.compile_query(fragment, dialect="postgres", paramstyle="numeric"), ("$1,$2,$3", ("a", "b", "c")))

    def test_compile_result_params_are_tuple(self):
        _sql, params = p.compile_query(p.sql_fragment(p.sql_param(1)), dialect="sqlite")
        self.assertIsInstance(params, tuple)


class ScalarParameterMatrixTest(unittest.TestCase):
    pass


_ACCEPTED_SCALARS = [
    ("none", None),
    ("true", True),
    ("false", False),
    ("zero", 0),
    ("negative_int", -99),
    ("large_int", 2**80),
    ("float", 3.25),
    ("negative_zero_float", -0.0),
    ("empty_string", ""),
    ("unicode_string", "unicode snowman"),
    ("bytes", b"\x00\xff"),
    ("decimal", Decimal("12.01")),
    ("date", date(2026, 1, 2)),
    ("datetime", datetime(2026, 1, 2, 3, 4, 5)),
    ("uuid", UUID("12345678-1234-5678-1234-567812345678")),
]


def _make_scalar_case(name, value):
    def test(self):
        sql, params = p.compile_query(p.sql_fragment("SELECT ", p.sql_param(value)), dialect="sqlite")
        self.assertEqual(sql, "SELECT ?")
        self.assertEqual(params, (value,))
    return test


for _name, _value in _ACCEPTED_SCALARS:
    setattr(ScalarParameterMatrixTest, "test_accepts_" + _name, _make_scalar_case(_name, _value))


class RejectedParameterMatrixTest(unittest.TestCase):
    pass


class _CustomObject:
    pass


_REJECTED_PARAMETERS = [
    ("object", object()),
    ("custom_object", _CustomObject()),
    ("list", []),
    ("tuple", (1,)),
    ("dict", {}),
    ("set", set()),
    ("frozenset", frozenset()),
    ("bytearray", bytearray()),
    ("memoryview", memoryview(b"x")),
    ("function", lambda: None),
    ("builtin_function", len),
    ("type_object", int),
    ("module", unittest),
    ("exception", ValueError("x")),
]


def _make_rejected_case(name, value):
    def test(self):
        assert_code(self, "INVALID_PARAMETER", p.compile_query, p.sql_fragment("SELECT ", p.sql_param(value)), dialect="sqlite")
    return test


for _name, _value in _REJECTED_PARAMETERS:
    setattr(RejectedParameterMatrixTest, "test_rejects_" + _name, _make_rejected_case(_name, _value))


class NonFiniteParameterTest(unittest.TestCase):
    def test_rejects_nan(self):
        assert_code(self, "INVALID_PARAMETER", p.compile_query, p.sql_fragment(p.sql_param(float("nan"))), dialect="sqlite")

    def test_rejects_positive_infinity(self):
        assert_code(self, "INVALID_PARAMETER", p.compile_query, p.sql_fragment(p.sql_param(float("inf"))), dialect="sqlite")

    def test_rejects_negative_infinity(self):
        assert_code(self, "INVALID_PARAMETER", p.compile_query, p.sql_fragment(p.sql_param(float("-inf"))), dialect="sqlite")

    def test_rejects_decimal_nan(self):
        assert_code(self, "INVALID_PARAMETER", p.compile_query, p.sql_fragment(p.sql_param(Decimal("NaN"))), dialect="sqlite")

    def test_rejects_decimal_infinity(self):
        assert_code(self, "INVALID_PARAMETER", p.compile_query, p.sql_fragment(p.sql_param(Decimal("Infinity"))), dialect="sqlite")

    def test_allow_non_finite_float_when_explicit(self):
        value = float("nan")
        _sql, params = p.compile_query(p.sql_fragment(p.sql_param(value)), dialect="sqlite", allow_non_finite=True)
        self.assertEqual(len(params), 1)
        self.assertTrue(math.isnan(params[0]))

    def test_allow_non_finite_decimal_when_explicit(self):
        value = Decimal("Infinity")
        _sql, params = p.compile_query(p.sql_fragment(p.sql_param(value)), dialect="sqlite", allow_non_finite=True)
        self.assertEqual(params, (value,))

    def test_allow_objects_explicitly_permits_custom_object(self):
        value = _CustomObject()
        _sql, params = p.compile_query(p.sql_fragment(p.sql_param(value)), dialect="sqlite", allow_objects=True)
        self.assertEqual(params, (value,))

    def test_allow_callables_explicitly_permits_callable(self):
        value = lambda: 1
        _sql, params = p.compile_query(p.sql_fragment(p.sql_param(value)), dialect="sqlite", allow_callables=True)
        self.assertEqual(params, (value,))


class CompileCapsAndOptionsTest(unittest.TestCase):
    def test_parameter_cap_is_enforced(self):
        fragment = p.sql_fragment(*[part for value in range(1001) for part in ((p.sql_param(value) if value else p.sql_param(value)), " ")])
        assert_code(self, "MAX_PARAMETERS", p.compile_query, fragment, dialect="sqlite")

    def test_exactly_1000_parameters_is_allowed(self):
        pieces = []
        for value in range(1000):
            pieces.append(p.sql_param(value))
            pieces.append(" ")
        sql, params = p.compile_query(p.sql_fragment(*pieces), dialect="sqlite")
        self.assertEqual(len(params), 1000)
        self.assertEqual(sql.count("?"), 1000)

    def test_lower_parameter_cap_is_enforced(self):
        fragment = p.sql_fragment(p.sql_param(1), p.sql_param(2))
        assert_code(self, "MAX_PARAMETERS", p.compile_query, fragment, dialect="sqlite", max_parameters=1)

    def test_sql_length_cap_is_enforced(self):
        fragment = p.sql_fragment("x" * 101)
        assert_code(self, "MAX_SQL_LENGTH", p.compile_query, fragment, dialect="sqlite", max_sql_length=100)

    def test_exact_sql_length_cap_is_allowed(self):
        fragment = p.sql_fragment("x" * 100)
        sql, _params = p.compile_query(fragment, dialect="sqlite", max_sql_length=100)
        self.assertEqual(sql, "x" * 100)

    def test_legal_depth_32_compiles(self):
        fragment = p.static_fragment("x")
        for _ in range(32):
            fragment = p.sql_fragment(fragment)
        self.assertEqual(p.compile_query(fragment, dialect="sqlite"), ("x", ()))

    def test_depth_33_fails_without_recursion_error(self):
        fragment = p.static_fragment("x")
        for _ in range(33):
            fragment = p.sql_fragment(fragment)
        assert_code(self, "MAX_FRAGMENT_DEPTH", p.compile_query, fragment, dialect="sqlite")

    def test_twenty_thousand_deep_fragment_fails_closed_not_with_recursion_error(self):
        fragment = p.static_fragment("x")
        for _ in range(20000):
            fragment = p.sql_fragment(fragment)
        try:
            p.compile_query(fragment, dialect="sqlite")
        except SqlCageError as exc:
            self.assertEqual(exc.code, CODE["MAX_FRAGMENT_DEPTH"])
        except RecursionError:
            self.fail("iterative compiler raised RecursionError")
        else:
            self.fail("depth cap was not enforced")

    def test_rejects_invalid_dialect(self):
        assert_code(self, "INVALID_DIALECT", p.compile_query, p.sql_fragment("x"), dialect="oracle")

    def test_rejects_invalid_paramstyle(self):
        assert_code(self, "INVALID_PARAMSTYLE", p.compile_query, p.sql_fragment("x"), dialect="sqlite", paramstyle="named")


class CompileInvalidOptionMatrixTest(unittest.TestCase):
    pass


def _make_invalid_option_case(name, keyword, value):
    def test(self):
        kwargs = {keyword: value}
        assert_code(self, "INVALID_OPTIONS", p.compile_query, p.sql_fragment("x"), dialect="sqlite", **kwargs)
    return test


_INVALID_OPTION_CASES = []
for _keyword in ("max_parameters", "max_sql_length", "max_fragment_depth"):
    for _label, _value in (
        ("zero", 0),
        ("negative", -1),
        ("bool", True),
        ("float", 1.5),
        ("string", "10"),
    ):
        _INVALID_OPTION_CASES.append((_keyword + "_" + _label, _keyword, _value))
_INVALID_OPTION_CASES.extend([
    ("max_parameters_above_hard_cap", "max_parameters", 1001),
    ("max_sql_length_above_hard_cap", "max_sql_length", 65537),
    ("max_fragment_depth_above_hard_cap", "max_fragment_depth", 33),
    ("allow_objects_nonbool", "allow_objects", 1),
    ("allow_callables_nonbool", "allow_callables", 1),
    ("allow_non_finite_nonbool", "allow_non_finite", 1),
])

for _name, _keyword, _value in _INVALID_OPTION_CASES:
    setattr(CompileInvalidOptionMatrixTest, "test_" + _name, _make_invalid_option_case(_name, _keyword, _value))


class SqlCageFactoryTest(unittest.TestCase):
    def test_cage_compile_uses_defaults(self):
        cage = p.SqlCage("sqlite")
        self.assertEqual(cage.compile(p.sql_fragment("SELECT ", p.sql_param(1))), ("SELECT ?", (1,)))

    def test_cage_compile_query_alias(self):
        cage = p.SqlCage("sqlite")
        self.assertEqual(cage.compile_query(p.sql_fragment("SELECT ", p.sql_param(1))), ("SELECT ?", (1,)))

    def test_cage_override_paramstyle(self):
        cage = p.SqlCage("postgres")
        self.assertEqual(
            cage.compile(p.sql_fragment(p.sql_param(1)), paramstyle="numeric"),
            ("$1", (1,)),
        )

    def test_cage_unknown_override_fails(self):
        cage = p.SqlCage("sqlite")
        assert_code(self, "INVALID_OPTIONS", cage.compile, p.sql_fragment("x"), unknown_option=True)

    def test_cage_is_immutable(self):
        cage = p.SqlCage("sqlite")
        with self.assertRaises(AttributeError):
            cage.dialect = "mysql"

    def test_cage_options_are_read_only_mapping(self):
        cage = p.SqlCage("sqlite")
        self.assertEqual(cage.options["dialect"], "sqlite")
        with self.assertRaises(TypeError):
            cage.options["dialect"] = "mysql"

    def test_cage_quote_identifier_uses_dialect(self):
        self.assertEqual(p.SqlCage("mysql").quote_identifier("users"), "`users`")
        self.assertEqual(p.SqlCage("postgres").quote_identifier("users"), '"users"')

    def test_cage_schema_defaults_to_cage_dialect(self):
        guard = p.SqlCage("mysql").schema({"users": ["id"]})
        self.assertEqual(guard.dialect, "mysql")

    def test_cage_sql_fragment_factory(self):
        cage = p.SqlCage("sqlite")
        self.assertEqual(cage.compile(cage.sql_fragment("SELECT ", p.sql_param(1))), ("SELECT ?", (1,)))

    def test_create_sql_cage_helper(self):
        cage = p.create_sql_cage(dialect="sqlite")
        self.assertIsInstance(cage, p.SqlCage)

    def test_create_sql_cage_rejects_bad_dialect(self):
        assert_code(self, "INVALID_DIALECT", p.create_sql_cage, dialect="bad")


if __name__ == "__main__":
    unittest.main()
