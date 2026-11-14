"""What importing a published package runs (`LoadReach`), resolved per module as Python binds names:
a decorated function or a dunder is not reached for being one, and `obj.f()` on an object is not
the module's `f` (reviews/pypi-98/10)."""

from __future__ import annotations

from typing import ClassVar

from cordon_scanner.analysis.python.reachability import LoadReach


class TestTheLoadReach:
    """Resolved per module, as Python binds names: `requests.get` is not the package's `get`."""

    PACKAGE: ClassVar[dict[str, str]] = {
        "p-1/pkg/__init__.py": (
            "from .core import boot\nfrom . import payload\nimport requests\nimport atexit\n"
            "boot()\npayload.run()\nrequests.get('x')\natexit.register(later)\n"
            "def later():\n    pass\ndef get():\n    pass\n"
        ),
        "p-1/pkg/core.py": (
            "from pkg.util import helper\nclass Server:\n    def __init__(self):\n        self.start()\n"
            "    def start(self):\n        pass\n    def other(self):\n        pass\n"
            "def boot():\n    helper()\n    Server()\n@app.route('/x')\ndef route():\n    pass\n"
        ),
        "p-1/pkg/util.py": "def helper():\n    pass\ndef unused():\n    pass\n",
        "p-1/pkg/payload.py": "def run():\n    pass\ndef update():\n    pass\n",
    }

    def test_what_import_runs_and_what_it_does_not(self) -> None:
        deferred = LoadReach.deferred_lines(self.PACKAGE, self.PACKAGE)
        names = {
            (path.rsplit("/", 1)[1], self.PACKAGE[path].splitlines()[first - 2].strip())
            for path, first, _last in deferred
        }
        assert names == {
            ("__init__.py", "def get():"),
            ("core.py", "def other(self):"),
            ("core.py", "def route():"),
            ("payload.py", "def update():"),
            ("util.py", "def unused():"),
        }


class TestReachWithoutMain:
    """`without_main`: the same roots minus `__main__.py`'s load statements -- what `import pkg` runs,
    as opposed to `python -m pkg` (reviews/pypi-98/19). Used by two composites only."""

    PACKAGE: ClassVar[dict[str, str]] = {
        "p-1/pkg/__init__.py": "from pkg.core import boot\nboot()\n",
        "p-1/pkg/__main__.py": "from pkg.cli import main\nmain()\n",
        "p-1/pkg/cli.py": "def main():\n    pass\n",
        "p-1/pkg/core.py": "def boot():\n    pass\n",
    }

    def test_a_body_only_main_reaches_is_deferred_without_main(self) -> None:
        both = LoadReach.deferred_lines(self.PACKAGE, self.PACKAGE)
        bare = LoadReach.deferred_lines(self.PACKAGE, self.PACKAGE, without_main=True)
        assert ("p-1/pkg/cli.py", 2, 2) not in both
        assert ("p-1/pkg/cli.py", 2, 2) in bare

    def test_a_body_init_reaches_is_run_either_way(self) -> None:
        bare = LoadReach.deferred_lines(self.PACKAGE, self.PACKAGE, without_main=True)
        assert ("p-1/pkg/core.py", 2, 2) not in bare


class TestWhatImportNeverRuns:
    """Code importing can never reach: a `__main__` block and a file no import statement can name
    (measured: 6 of #59's 30 newly blocked benign, reviews/pypi-98/11)."""

    def test_a_main_guard_block_is_not_run_by_import(self) -> None:
        package = {
            "p-1/pkg/__init__.py": "from . import cli\n",
            "p-1/pkg/cli.py": "import os\nif __name__ == '__main__':\n    os.system('make')\n",
        }
        deferred = LoadReach.deferred_lines(package, package)
        assert ("p-1/pkg/cli.py", 3, 3) in deferred

    def test_a_file_no_import_can_name_is_not_a_module(self) -> None:
        from cordon_scanner.ecosystems.packages.pypi import PypiEcosystem

        members = {
            m: m
            for m in (
                "p-1.0/bootstrap-buildout.py",
                "p-1.0/pkg/__init__.py",
                "p-1.0/pkg/run-me.py",
                "p-1.0/pkg/core.py",
                "p-1.0/my-tools/helper.py",
                "p-1.0/src/pkg2/mod.py",
            )
        }
        assert PypiEcosystem().import_modules(members) == {
            "p-1.0/pkg/__init__.py",
            "p-1.0/pkg/core.py",
            "p-1.0/src/pkg2/mod.py",
        }

    def test_a_function_defined_and_run_inside_a_reached_one_is_run(self) -> None:
        package = {
            "p-1/pkg/__init__.py": (
                "def _s():\n"
                "    import threading\n"
                "    def _r():\n"
                "        pass\n"
                "    def _q():\n"
                "        pass\n"
                "    def _never():\n"
                "        pass\n"
                "    threading.Thread(target=_r).start()\n"
                "    _q()\n"
                "_s()\n"
            ),
        }
        deferred = LoadReach.deferred_lines(package, package)
        assert {first for _path, first, _last in deferred} == {8}
