"""Absolute imports in an install hook's closure resolve from the directory the hook runs from."""

from __future__ import annotations

import json
from typing import ClassVar

from cordon_scanner.detect.base import FileUnit
from cordon_scanner.engine.closure import ImportClosure
from cordon_scanner.engine.entries import PackageEntries
from cordon_scanner.foundation.content import FileContent


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


# Item 72, the owner's ruling of 3 Nov (a strict scanner): what a published package's own dev, build and
# start scripts run is reached code. Measured on the npm work set: 4,976 archives with such a script or a
# root tool configuration; +4 malware and +5 benign blocked against the release head.


class ReachKit:
    @staticmethod
    def units(manifest: dict, *files: str) -> list[FileUnit]:
        out = [
            FileUnit(
                content=FileContent.from_bytes(
                    "demo.tgz!package/package.json", json.dumps(manifest).encode()
                )
            )
        ]
        out += [
            FileUnit(content=FileContent.from_bytes(f"demo.tgz!{f}", b"x = 1\n")) for f in files
        ]
        return out

    @staticmethod
    def reached(manifest: dict, *files: str) -> set[str]:
        got = PackageEntries.project_run(ReachKit.units(manifest, *files), "npm")
        return {p.split("!", 1)[1] for p in got}


class TestProjectReach:
    def test_the_file_a_start_script_runs_is_reached(self) -> None:
        manifest = {"name": "demo", "version": "1.0.0", "scripts": {"start": "node server.js"}}
        assert "package/server.js" in ReachKit.reached(manifest, "package/server.js")

    def test_a_root_tool_configuration_is_reached_when_a_project_script_exists(self) -> None:
        manifest = {"name": "demo", "version": "1.0.0", "scripts": {"dev": "next dev"}}
        got = ReachKit.reached(manifest, "package/next.config.mjs", "package/vite.config.ts")
        assert got == {"package/next.config.mjs", "package/vite.config.ts"}

    def test_a_configuration_below_the_root_is_not(self) -> None:
        manifest = {"name": "demo", "version": "1.0.0", "scripts": {"build": "vite build"}}
        assert ReachKit.reached(manifest, "package/examples/vite.config.ts") == set()

    def test_a_package_with_no_project_script_reaches_nothing_this_way(self) -> None:
        manifest = {"name": "demo", "version": "1.0.0", "scripts": {"test": "node t.js"}}
        assert ReachKit.reached(manifest, "package/t.js", "package/next.config.mjs") == set()

    def test_the_pre_and_post_scripts_count(self) -> None:
        manifest = {"name": "demo", "version": "1.0.0", "scripts": {"prestart": "node setup.js"}}
        assert "package/setup.js" in ReachKit.reached(manifest, "package/setup.js")
