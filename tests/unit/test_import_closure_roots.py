"""Absolute imports in an install hook's closure resolve from the directory the hook runs from."""

from __future__ import annotations

from typing import ClassVar

from cordon_scanner.core.closure import ImportClosure


class TestAbsoluteImportsResolveFromTheHooksDirectory:
    """`python setup.py` puts its own directory first on `sys.path`, so `import pkg.cmd` written
    anywhere in the closure means `<root>/pkg/cmd.py` (review 98: randrange's `setup/` package)."""

    ROOT = "p-0.0.2"
    SOURCES: ClassVar[dict[str, str]] = {
        f"{ROOT}/setup.py": "from setuptools import setup\nfrom setup import kwargs\nsetup(**kwargs)\n",
        f"{ROOT}/setup/__init__.py": "import setup.install_command\nkwargs = {}\n",
        f"{ROOT}/setup/install_command.py": "from setup.utils import helper\n",
        f"{ROOT}/setup/utils.py": "def helper():\n    return 1\n",
        f"{ROOT}/setup/unused.py": "VALUE = 1\n",
    }

    def test_a_package_beside_setup_py_is_followed_through_its_own_imports(self) -> None:
        reached = ImportClosure.resolve({f"{self.ROOT}/setup.py"}, self.SOURCES)
        assert f"{self.ROOT}/setup/install_command.py" in reached
        assert f"{self.ROOT}/setup/utils.py" in reached

    def test_a_module_nothing_imports_is_not(self) -> None:
        reached = ImportClosure.resolve({f"{self.ROOT}/setup.py"}, self.SOURCES)
        assert f"{self.ROOT}/setup/unused.py" not in reached
