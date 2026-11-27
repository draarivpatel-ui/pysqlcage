from __future__ import annotations

import ast
import os
import re
import subprocess
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def repository_files():
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        if result.returncode == 0 and result.stdout:
            names = [name for name in result.stdout.decode("utf-8").split("\x00") if name]
            if names:
                return sorted(names)
    except (OSError, subprocess.SubprocessError):
        pass
    output = []
    for root, dirs, files in os.walk(REPO_ROOT):
        dirs[:] = [item for item in dirs if item not in {".git", "__pycache__", "build", "dist"}]
        for name in files:
            if name.endswith((".pyc", ".pyo")):
                continue
            output.append(os.path.relpath(os.path.join(root, name), REPO_ROOT))
    return sorted(output)


def read_repo_file(name):
    with open(os.path.join(REPO_ROOT, name), "rb") as handle:
        return handle.read()


class RepositoryHygieneTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = repository_files()
        cls.contents = {name: read_repo_file(name) for name in cls.files}

    def test_git_file_inventory_is_nonempty(self):
        self.assertGreater(len(self.files), 25)
        self.assertIn("pyproject.toml", self.files)
        self.assertIn("src/pysqlcage/__init__.py", self.files)
        self.assertIn("src/pysqlcage/py.typed", self.files)

    def test_git_inventory_contains_all_test_files(self):
        test_files = [name for name in self.files if name.startswith("tests/test_") and name.endswith(".py")]
        self.assertGreaterEqual(len(test_files), 6)

    def test_no_em_or_en_dash_bytes(self):
        em_dash = bytes([0xE2, 0x80, 0x94])
        en_dash = bytes([0xE2, 0x80, 0x93])
        offenders = [name for name, data in self.contents.items() if em_dash in data or en_dash in data]
        self.assertEqual(offenders, [])

    def test_no_crlf_line_endings(self):
        offenders = [name for name, data in self.contents.items() if b"\r\n" in data or b"\r" in data]
        self.assertEqual(offenders, [])

    def test_no_machine_local_paths(self):
        needles = [
            b"/" + b"Users" + b"/",
            b"/" + b"home" + b"/",
            b"/" + b"private" + b"/tmp/",
        ]
        offenders = []
        for name, data in self.contents.items():
            if any(needle in data for needle in needles):
                offenders.append(name)
        self.assertEqual(offenders, [])

    def test_no_private_email_or_location_markers(self):
        first = "draarivpatel" + "@" + "gmail.com"
        second = "proroblox286" + "@" + "gmail.com"
        street = "5019 " + "Tanyard"
        needles = [first.encode(), second.encode(), street.encode()]
        offenders = []
        for name, data in self.contents.items():
            lowered = data.lower()
            if any(needle.lower() in lowered for needle in needles):
                offenders.append(name)
        self.assertEqual(offenders, [])

    def test_no_vendor_shaped_credential_values(self):
        patterns = [
            rb"gh" + rb"p_[A-Za-z0-9]{20,}",
            rb"gh" + rb"o_[A-Za-z0-9]{20,}",
            rb"github_pat_[A-Za-z0-9_]{20,}",
            rb"sk" + rb"_(?:live|test)_[A-Za-z0-9]{12,}",
            rb"AK" + rb"IA[0-9A-Z]{16}",
            rb"xox" + rb"[baprs]-[A-Za-z0-9-]{10,}",
            rb"AI" + rb"za[A-Za-z0-9_-]{20,}",
            rb"npm" + rb"_[A-Za-z0-9]{30,}",
            rb"pypi" + rb"-[A-Za-z0-9_-]{20,}",
        ]
        offenders = []
        for name, data in self.contents.items():
            if any(re.search(pattern, data) for pattern in patterns):
                offenders.append(name)
        self.assertEqual(offenders, [])

    def test_no_tracked_python_bytecode(self):
        offenders = [name for name in self.files if name.endswith((".pyc", ".pyo")) or "__pycache__" in name.split("/")]
        self.assertEqual(offenders, [])

    def test_runtime_dependencies_are_empty(self):
        data = self.contents["pyproject.toml"].decode("utf-8")
        self.assertIn("dependencies = []", data)

    def test_requires_python_39_plus(self):
        data = self.contents["pyproject.toml"].decode("utf-8")
        self.assertIn('requires-python = ">=3.9"', data)

    def test_typed_marker_is_packaged(self):
        data = self.contents["pyproject.toml"].decode("utf-8")
        self.assertIn("py.typed", data)
        self.assertIn("src/pysqlcage/py.typed", self.files)

    def test_src_layout_is_used(self):
        data = self.contents["pyproject.toml"].decode("utf-8")
        self.assertIn('package-dir = { "" = "src" }', data)
        self.assertIn('where = ["src"]', data)

    def test_project_urls_are_accurate(self):
        data = self.contents["pyproject.toml"].decode("utf-8")
        self.assertIn("https://github.com/draarivpatel-ui/pysqlcage", data)
        self.assertNotIn("example.com", data)

    def test_cli_entry_point_is_configured(self):
        data = self.contents["pyproject.toml"].decode("utf-8")
        self.assertIn('pysqlcage = "pysqlcage.cli:main"', data)

    def test_no_python_310_only_syntax_in_source(self):
        offenders = []
        for name in self.files:
            if not name.endswith(".py"):
                continue
            text = self.contents[name].decode("utf-8")
            if re.search(r"^\s*match\s+[^\n]+:\s*$", text, re.MULTILINE) or re.search(r"^\s*case\s+[^\n]+:\s*$", text, re.MULTILINE):
                offenders.append(name)
            if "toml" + "lib" in text:
                offenders.append(name)
        self.assertEqual(offenders, [])

    def test_all_python_files_parse(self):
        errors = []
        for name in self.files:
            if name.endswith(".py"):
                try:
                    ast.parse(self.contents[name], filename=name)
                except SyntaxError as exc:
                    errors.append((name, str(exc)))
        self.assertEqual(errors, [])

    def test_python_files_import_future_annotations(self):
        offenders = []
        for name in self.files:
            if name.endswith(".py") and not name.startswith("tests/"):
                text = self.contents[name].decode("utf-8")
                if not text.startswith("from __future__ import annotations"):
                    offenders.append(name)
        self.assertEqual(offenders, [])

    def test_ci_matrix_has_python_39_through_313(self):
        data = self.contents[".github/workflows/ci.yml"].decode("utf-8")
        for version in ("3.9", "3.10", "3.11", "3.12", "3.13"):
            self.assertIn('"' + version + '"', data)
        self.assertIn("ubuntu-24.04", data)
        self.assertIn("python3 -m unittest discover -s tests", data)

    def test_ci_checks_wheel_and_sdist_contents(self):
        data = self.contents[".github/workflows/ci.yml"].decode("utf-8")
        self.assertIn("pysqlcage/py.typed", data)
        self.assertIn("zipfile", data)
        self.assertIn("tarfile", data)
        self.assertIn("python3 -m build", data)

    def test_publish_workflow_uses_oidc_without_token_secret(self):
        data = self.contents[".github/workflows/publish.yml"].decode("utf-8")
        self.assertIn("id-token: write", data)
        self.assertIn("environment:", data)
        self.assertIn("name: pypi", data)
        self.assertIn("pypa/gh-action-pypi-publish@release/v1", data)
        self.assertNotIn("PYPI" + "_TOKEN", data)
        self.assertNotIn("password:", data)

    def test_readme_is_honest_about_pypi_pending_state(self):
        data = self.contents["README.md"].decode("utf-8")
        self.assertIn("prepared for its first PyPI release", data)
        self.assertIn("does not claim that the package has already been published", data)

    def test_readme_documents_threat_model_and_sqlite_integration(self):
        data = self.contents["README.md"].decode("utf-8")
        self.assertIn("Threat model", data)
        self.assertIn("sqlite3.connect", data)
        self.assertIn("PostgreSQL", data)
        self.assertIn("MySQL", data)
        self.assertIn("SQLite", data)

    def test_license_is_mit(self):
        data = self.contents["LICENSE"].decode("utf-8")
        self.assertTrue(data.startswith("MIT License"))

    def test_no_ai_commit_trailer_in_repository_files(self):
        marker = ("Co-Authored" + "-By").encode()
        offenders = [name for name, data in self.contents.items() if marker in data]
        self.assertEqual(offenders, [])

    def test_gitignore_excludes_bytecode_and_build_output(self):
        data = self.contents[".gitignore"].decode("utf-8")
        for needle in ("__pycache__/", "*.py[cod]", "build/", "dist/"):
            self.assertIn(needle, data)

    def test_good_first_issues_has_ten_specs(self):
        data = self.contents["docs/GOOD_FIRST_ISSUES.md"].decode("utf-8")
        count = len(re.findall(r"^\d+\. ", data, re.MULTILINE))
        self.assertEqual(count, 10)

    def test_all_text_files_decode_as_utf8(self):
        errors = []
        for name, data in self.contents.items():
            try:
                data.decode("utf-8")
            except UnicodeDecodeError as exc:
                errors.append((name, str(exc)))
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
