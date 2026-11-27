from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ENV = dict(os.environ)
ENV["PYTHONPATH"] = str(REPO_ROOT / "src")


def run_cli(args, input_bytes=None):
    return subprocess.run(
        [sys.executable, "-m", "pysqlcage"] + list(args),
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=ENV,
        timeout=10,
        check=False,
    )


class CliBasicTest(unittest.TestCase):
    def test_safe_stdin_exits_zero(self):
        result = run_cli(["audit", "-", "--dialect", "sqlite"], b"SELECT 1\n")
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"safe", result.stdout)
        self.assertEqual(result.stderr, b"")

    def test_unsafe_stdin_exits_one(self):
        result = run_cli(["audit", "-", "--dialect", "sqlite"], b"SELECT 1; DROP TABLE users\n")
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"unsafe", result.stdout)
        self.assertIn(b"PYSQLCAGE_MULTI_STATEMENT", result.stdout)

    def test_json_safe_stdin_shape(self):
        result = run_cli(["audit", "-", "--dialect", "postgres", "--json"], b"SELECT 1\n")
        self.assertEqual(result.returncode, 0)
        payload = json.loads(result.stdout.decode("utf-8"))
        self.assertTrue(payload["safe"])
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["dialect"], "postgres")
        self.assertEqual(payload["input"], "<stdin>")
        self.assertIn("stats", payload)

    def test_json_unsafe_findings_shape(self):
        result = run_cli(["audit", "-", "--dialect", "sqlite", "--json"], b"SELECT 1; DROP TABLE users\n")
        self.assertEqual(result.returncode, 1)
        payload = json.loads(result.stdout.decode("utf-8"))
        self.assertFalse(payload["safe"])
        codes = [finding["code"] for finding in payload["findings"]]
        self.assertIn("PYSQLCAGE_MULTI_STATEMENT", codes)
        self.assertIn("PYSQLCAGE_DANGEROUS_KEYWORD", codes)

    def test_safe_file_exits_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "query.sql"
            path.write_text("SELECT 1\n", encoding="utf-8")
            result = run_cli(["audit", str(path), "--dialect", "sqlite"])
        self.assertEqual(result.returncode, 0)

    def test_unsafe_file_exits_one(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "query.sql"
            path.write_text("DROP TABLE users\n", encoding="utf-8")
            result = run_cli(["audit", str(path), "--dialect", "sqlite"])
        self.assertEqual(result.returncode, 1)

    def test_missing_file_exits_two(self):
        result = run_cli(["audit", "definitely-missing-pysqlcage-file.sql"])
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"error", result.stderr)

    def test_invalid_dialect_exits_two(self):
        result = run_cli(["audit", "-", "--dialect", "oracle"], b"SELECT 1")
        self.assertEqual(result.returncode, 2)

    def test_no_command_exits_two(self):
        result = run_cli([])
        self.assertEqual(result.returncode, 2)

    def test_version_exits_zero(self):
        result = run_cli(["--version"])
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"pysqlcage 1.0.0", result.stdout)

    def test_invalid_utf8_file_exits_two(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.sql"
            path.write_bytes(b"SELECT \xff")
            result = run_cli(["audit", str(path)])
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"UTF-8", result.stderr)

    def test_invalid_utf8_stdin_exits_two(self):
        result = run_cli(["audit", "-"], b"SELECT \xff")
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"UTF-8", result.stderr)

    def test_stdin_oversize_exits_two(self):
        result = run_cli(["audit", "-"], b"x" * (1024 * 1024 + 1))
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"byte limit", result.stderr)


class CliFileDefenseTest(unittest.TestCase):
    def test_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            result = run_cli(["audit", directory])
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"directory", result.stderr)

    def test_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.sql"
            target.write_text("SELECT 1", encoding="utf-8")
            link = Path(directory) / "link.sql"
            link.symlink_to(target)
            result = run_cli(["audit", str(link)])
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"symlink", result.stderr)

    def test_fifo_is_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / "input.fifo"
            os.mkfifo(str(fifo))
            result = run_cli(["audit", str(fifo)])
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"FIFO", result.stderr)

    def test_device_is_rejected(self):
        if not os.path.exists("/dev/null"):
            self.skipTest("/dev/null is unavailable")
        result = run_cli(["audit", "/dev/null"])
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"device", result.stderr)

    def test_oversized_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.sql"
            with path.open("wb") as handle:
                handle.seek(1024 * 1024)
                handle.write(b"x")
            result = run_cli(["audit", str(path)])
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"byte limit", result.stderr)

    def test_bidi_path_is_neutralized_in_error(self):
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / "bad\u202esql"
            link.symlink_to(Path(directory) / "target.sql")
            result = run_cli(["audit", str(link)])
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("\u202e".encode("utf-8"), result.stderr)
        self.assertIn(b"\\u202e", result.stderr)

    def test_ansi_escape_in_path_is_neutralized(self):
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / "bad\x1b[31m.sql"
            link.symlink_to(Path(directory) / "target.sql")
            result = run_cli(["audit", str(link)])
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(b"\x1b", result.stderr)
        self.assertIn(b"\\x1b", result.stderr)

    def test_json_escapes_bidi_in_input_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "safe\u202e.sql"
            path.write_text("SELECT 1", encoding="utf-8")
            result = run_cli(["audit", str(path), "--json"])
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("\u202e".encode("utf-8"), result.stdout)

    def test_error_output_is_single_line(self):
        result = run_cli(["audit", "missing\ninjected.sql"])
        self.assertEqual(result.returncode, 2)
        self.assertEqual(len(result.stderr.splitlines()), 1)


class CliDialectMatrixTest(unittest.TestCase):
    pass


def _make_dialect_case(dialect):
    def test(self):
        result = run_cli(["audit", "-", "--dialect", dialect, "--json"], b"SELECT 1")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout.decode("utf-8"))["dialect"], dialect)
    return test


for _dialect in ("postgres", "mysql", "sqlite"):
    setattr(CliDialectMatrixTest, "test_" + _dialect, _make_dialect_case(_dialect))


class CliDialectBehaviorTest(unittest.TestCase):
    def test_mysql_executable_comment_is_unsafe(self):
        result = run_cli(["audit", "-", "--dialect", "mysql"], b"SELECT 1 /*!50000 DROP TABLE users */")
        self.assertEqual(result.returncode, 1)

    def test_postgres_dollar_quote_is_safe(self):
        result = run_cli(["audit", "-", "--dialect", "postgres"], b"SELECT $$DROP TABLE users$$")
        self.assertEqual(result.returncode, 0)

    def test_sqlite_dollar_text_is_unsafe(self):
        result = run_cli(["audit", "-", "--dialect", "sqlite"], b"SELECT $tag$DROP TABLE users$tag$")
        self.assertEqual(result.returncode, 1)

    def test_mysql_dash_no_space_is_safe(self):
        result = run_cli(["audit", "-", "--dialect", "mysql"], b"SELECT 1--x")
        self.assertEqual(result.returncode, 0)

    def test_mysql_dash_space_is_unsafe(self):
        result = run_cli(["audit", "-", "--dialect", "mysql"], b"SELECT 1-- x")
        self.assertEqual(result.returncode, 1)


class CliMaxSqlLengthTest(unittest.TestCase):
    def test_valid_max_sql_length_safe_and_unsafe(self):
        safe_result = run_cli(["audit", "-", "--max-sql-length", "16"], b"SELECT 1")
        self.assertEqual(safe_result.returncode, 0)
        self.assertIn(b"safe", safe_result.stdout)

        unsafe_result = run_cli(["audit", "-", "--max-sql-length", "5"], b"SELECT 1")
        self.assertEqual(unsafe_result.returncode, 1)
        self.assertIn(b"PYSQLCAGE_MAX_SQL_LENGTH", unsafe_result.stdout)

    def test_boundary_values_min_and_max(self):
        min_safe = run_cli(["audit", "-", "--max-sql-length", "1"], b"1")
        self.assertEqual(min_safe.returncode, 0)

        min_unsafe = run_cli(["audit", "-", "--max-sql-length", "1"], b"12")
        self.assertEqual(min_unsafe.returncode, 1)
        self.assertIn(b"PYSQLCAGE_MAX_SQL_LENGTH", min_unsafe.stdout)

        max_safe = run_cli(["audit", "-", "--max-sql-length", "16777216"], b"SELECT 1")
        self.assertEqual(max_safe.returncode, 0)

    def test_zero_rejected_with_exit_two(self):
        result = run_cli(["audit", "-", "--max-sql-length", "0"], b"SELECT 1")
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"error", result.stderr)

    def test_negative_rejected_with_exit_two(self):
        for flag in ("--max-sql-length=-1", "--max-sql-length=-100"):
            result = run_cli(["audit", "-", flag], b"SELECT 1")
            self.assertEqual(result.returncode, 2)
            self.assertIn(b"error", result.stderr)

    def test_boolean_like_rejected_with_exit_two(self):
        for raw in ("true", "True", "false", "False"):
            result = run_cli(["audit", "-", "--max-sql-length", raw], b"SELECT 1")
            self.assertEqual(result.returncode, 2)
            self.assertIn(b"error", result.stderr)

    def test_oversized_rejected_with_exit_two(self):
        for raw in ("16777217", "999999999999"):
            result = run_cli(["audit", "-", "--max-sql-length", raw], b"SELECT 1")
            self.assertEqual(result.returncode, 2)
            self.assertIn(b"error", result.stderr)

    def test_control_characters_neutralized_in_error(self):
        ansi_result = run_cli(["audit", "-", "--max-sql-length", "10\x1b[31m"], b"SELECT 1")
        self.assertEqual(ansi_result.returncode, 2)
        self.assertNotIn(b"\x1b", ansi_result.stderr)
        self.assertIn(b"\\x1b", ansi_result.stderr)

        bidi_result = run_cli(["audit", "-", "--max-sql-length", "10\u202e"], b"SELECT 1")
        self.assertEqual(bidi_result.returncode, 2)
        self.assertNotIn("\u202e".encode("utf-8"), bidi_result.stderr)
        self.assertIn(b"\\u202e", bidi_result.stderr)

        newline_result = run_cli(["audit", "-", "--max-sql-length", "10\ninjected"], b"SELECT 1")
        self.assertEqual(newline_result.returncode, 2)
        self.assertEqual(len(newline_result.stderr.splitlines()), 1)
        self.assertIn(b"\\n", newline_result.stderr)

    def test_json_output_reflects_max_sql_length_threshold(self):
        query = b"SELECT 1"
        safe_result = run_cli(["audit", "-", "--max-sql-length", "8", "--json"], query)
        self.assertEqual(safe_result.returncode, 0)
        safe_payload = json.loads(safe_result.stdout.decode("utf-8"))
        self.assertTrue(safe_payload["safe"])
        self.assertEqual(safe_payload["findings"], [])

        unsafe_result = run_cli(["audit", "-", "--max-sql-length", "7", "--json"], query)
        self.assertEqual(unsafe_result.returncode, 1)
        unsafe_payload = json.loads(unsafe_result.stdout.decode("utf-8"))
        self.assertFalse(unsafe_payload["safe"])
        self.assertEqual(len(unsafe_payload["findings"]), 1)
        self.assertEqual(unsafe_payload["findings"][0]["code"], "PYSQLCAGE_MAX_SQL_LENGTH")
        self.assertEqual(unsafe_payload["findings"][0]["index"], 7)


if __name__ == "__main__":
    unittest.main()
