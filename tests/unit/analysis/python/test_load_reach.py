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
