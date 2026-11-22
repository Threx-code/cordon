"""A directory scan (a cloned repository) reads as running the Python files a package runs, and a running file no reader can take to its end is a
gap when it names an act.

The archive route has done this since 09 3a; a plain directory goes through the context worker's tree route, which did not call it. Running
here: `setup.py` and what it imports, the `__init__.py` of a top-level package and what it imports, and the modules `pyproject.toml` or `setup.cfg`
name for console scripts and entry points. Inert inputs written for the test.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config

GAP = "OPERATIONAL.SOURCE.UNPARSED"
RUNNING = "SUSPECT.SOURCE.UNPARSED_RUNNING.001"
BAD = b"exec('x')\ndef f(:\n"  # an act in it, and no grammar takes it
BAD_QUIET = b"def f(:\n"  # nothing in it that could run its pieces
GOOD = b"def f(a):\n    return [a, (a, 1)]\n"


class Repo:
    @staticmethod
    def scan(folder: Path, files: dict[str, bytes]):
        for name, body in files.items():
            target = folder / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
        return Scanner(Config.default().with_overrides(use_cache=False)).scan(folder)

    @staticmethod
    def gaps(result) -> set[str]:
        return {rule for rule, _ in result.content_gaps}

    @staticmethod
    def rules(result) -> set[str]:
        return {f.rule_id for f in result.active}


class TestWhatRuns:
    @pytest.mark.parametrize(
        ("files", "why"),
        [
            (
                {
                    "setup.py": b"import helper\nfrom setuptools import setup\nsetup()\n",
                    "helper.py": BAD,
                },
                "imported by setup.py",
            ),
            (
                {"pkg/__init__.py": BAD, "setup.py": b"from setuptools import setup\nsetup()\n"},
                "a top-level package's __init__",
            ),
            (
                {"src/pkg/__init__.py": BAD, "pyproject.toml": b"[project]\nname = 'x'\n"},
                "a package under src",
            ),
            (
                {"pkg/__init__.py": b"from . import core\n", "pkg/core.py": BAD},
                "imported relatively by __init__",
            ),
            (
                {
                    "pyproject.toml": b"[project]\nname = 'x'\n[project.scripts]\ncli = 'pkg.cli:main'\n",
                    "pkg/cli.py": BAD,
                },
                "a [project.scripts] module",
            ),
            (
                {
                    "pyproject.toml": b"[project]\nname = 'x'\n[project.entry-points.'x.plugins']\np = 'pkg.plug:run'\n",
                    "pkg/plug.py": BAD,
                },
                "a [project.entry-points] module",
            ),
            (
                {
                    "pyproject.toml": b"[tool.poetry]\nname = 'x'\n[tool.poetry.scripts]\ncli = 'pkg.cli:main'\n",
                    "pkg/cli.py": BAD,
                },
                "a poetry script module",
            ),
            (
                {
                    "setup.cfg": b"[options.entry_points]\nconsole_scripts =\n    cli = pkg.cli:main\n",
                    "pkg/cli.py": BAD,
                },
                "a setup.cfg console script",
            ),
        ],
    )
    def test_a_running_file_that_does_not_parse_and_names_an_act_is_a_gap(
        self, tmp_path: Path, files: dict[str, bytes], why: str
    ) -> None:
        result = Repo.scan(tmp_path, files)
        assert GAP in Repo.gaps(result), why
        assert result.content_complete is False

    def test_the_running_verdict_is_given_too(self, tmp_path: Path) -> None:
        result = Repo.scan(tmp_path, {"pkg/__init__.py": BAD})
        assert RUNNING in Repo.rules(result)

    def test_a_running_file_that_names_nothing_is_said_and_not_a_gap(self, tmp_path: Path) -> None:
        result = Repo.scan(tmp_path, {"pkg/__init__.py": BAD_QUIET})
        assert "OPERATIONAL.SOURCE.BROKEN" in Repo.rules(result)
        assert GAP not in Repo.gaps(result)


class TestWhatIsLeftAlone:
    @pytest.mark.parametrize(
        "files",
        [
            {"other.py": BAD, "setup.py": b"from setuptools import setup\nsetup()\n"},
            {"tests/test_x.py": BAD, "pkg/__init__.py": GOOD},
            {"docs/conf.py": BAD, "pkg/__init__.py": GOOD},
            {"pkg/__init__.py": GOOD, "pkg/unused.py": BAD},
            {"pkg/sub/__init__.py": BAD, "pkg/__init__.py": GOOD},
        ],
    )
    def test_a_file_nothing_runs_is_not_reported_however_broken(
        self, tmp_path: Path, files: dict[str, bytes]
    ) -> None:
        result = Repo.scan(tmp_path, files)
        assert GAP not in Repo.gaps(result)
        assert RUNNING not in Repo.rules(result)

    def test_a_package_that_parses_is_not_reported(self, tmp_path: Path) -> None:
        result = Repo.scan(
            tmp_path,
            {
                "pkg/__init__.py": GOOD,
                "pkg/cli.py": GOOD,
                "pyproject.toml": b"[project.scripts]\ncli = 'pkg.cli:main'\n",
            },
        )
        assert GAP not in Repo.gaps(result)
        assert not Repo.rules(result) & {RUNNING, "OPERATIONAL.SOURCE.BROKEN"}

    @pytest.mark.parametrize(
        "text", [b"[not toml", b"[project]\nscripts = 5\n", b"[tool.poetry.scripts]\ncli = 7\n"]
    )
    def test_a_manifest_that_is_not_one_is_no_crash_and_names_nothing(
        self, tmp_path: Path, text: bytes
    ) -> None:
        result = Repo.scan(tmp_path, {"pyproject.toml": text, "other.py": BAD})
        assert GAP not in Repo.gaps(result)
