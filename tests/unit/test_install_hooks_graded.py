"""npm install hooks graded by what they run (review 98, FP-1).

The benign commands are the most frequent ones that blocked real packages in the 200K corpus:
74 defensive placeholders (`echo please use the private registry && exit 1`), 58 `npx only-allow
pnpm`, `nuxt prepare`, `typings install`, a script that runs another script. The evasions are the
same commands with the tool's package swapped for a lookalike, or a step that leaves the package.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config

RULE = "SUSPECT.INSTALL.SCRIPT.001"


class HookKit:
    @staticmethod
    def findings(tmp_path: Path, scripts: dict[str, str], deps: dict[str, str] | None = None):
        manifest = {"name": "p", "version": "1.0.0", "scripts": scripts}
        if deps:
            manifest["devDependencies"] = deps
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, text in (
                ("package/package.json", json.dumps(manifest)),
                ("package/index.js", "module.exports = 1;\n"),
            ):
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        target = tmp_path / "p-1.0.0.tgz"
        target.write_bytes(buffer.getvalue())
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(target)
        return [f for f in result.findings if f.rule_id == RULE]


class TestStandardHooksAreQuiet:
    @pytest.mark.parametrize(
        "scripts",
        [
            {"postinstall": "echo please use the private registry && exit 1"},
            {"preinstall": "npx only-allow pnpm"},
            {"postinstall": "nuxt prepare"},
            {"postinstall": "typings install"},
            {"postinstall": "npm run build", "build": "tsc -p ."},
            {"postinstall": "npm run setup", "setup": "npm run build", "build": "node-gyp rebuild"},
            {"postinstall": "cd native && node-gyp rebuild"},
            {"postinstall": "opencollective-postinstall || true"},
            {"postinstall": "env PKG_CONFIG_PATH=./build/share/pkgconfig node-gyp rebuild"},
            {"postinstall": "./node_modules/.bin/bower install"},
            {"postinstall": "npx patch-package"},
            {"postinstall": "rm -rf node_modules/@types/react-native"},
            {"postinstall": "test -d dist || npm run build || true", "build": "tsc"},
            {"postinstall": "[ -f dist/index.js ] || npm run build", "build": "tsc"},
        ],
    )
    def test_no_finding(self, tmp_path: Path, scripts: dict[str, str]) -> None:
        assert HookKit.findings(tmp_path, scripts) == []

    def test_a_tool_declared_from_the_registry(self, tmp_path: Path) -> None:
        found = HookKit.findings(tmp_path, {"postinstall": "husky install"}, {"husky": "^9.0.0"})
        assert found == []


class TestTheSameShapesStillReport:
    def test_a_tool_whose_package_is_not_from_the_registry(self, tmp_path: Path) -> None:
        found = HookKit.findings(
            tmp_path, {"postinstall": "husky install"}, {"husky": "github:someone/husky"}
        )
        assert found

    def test_an_aliased_tool(self, tmp_path: Path) -> None:
        found = HookKit.findings(
            tmp_path, {"preinstall": "npx only-allow pnpm"}, {"only-allow": "npm:other@1"}
        )
        assert found

    def test_a_script_chain_that_ends_in_something_else(self, tmp_path: Path) -> None:
        found = HookKit.findings(tmp_path, {"postinstall": "npm run setup", "setup": "./bin/run"})
        assert found

    def test_a_script_that_is_not_there(self, tmp_path: Path) -> None:
        assert HookKit.findings(tmp_path, {"postinstall": "npm run missing"})

    def test_leaving_the_package(self, tmp_path: Path) -> None:
        assert HookKit.findings(tmp_path, {"postinstall": "cd ../.. && node-gyp rebuild"})

    def test_an_assignment_that_runs_something(self, tmp_path: Path) -> None:
        assert HookKit.findings(tmp_path, {"postinstall": "X=$(./fetch) node-gyp rebuild"})

    def test_removing_outside_the_package(self, tmp_path: Path) -> None:
        assert HookKit.findings(tmp_path, {"postinstall": "rm -rf node_modules/../../x"})

    def test_a_file_test_outside_the_package(self, tmp_path: Path) -> None:
        assert HookKit.findings(tmp_path, {"postinstall": "test -d ~/.ssh || ./setup"})

    def test_a_file_test_before_an_unknown_step(self, tmp_path: Path) -> None:
        assert HookKit.findings(tmp_path, {"postinstall": "test -d dist || ./bin/fetch"})

    def test_a_guard_followed_by_a_step(self, tmp_path: Path) -> None:
        assert HookKit.findings(tmp_path, {"preinstall": "npx only-allow pnpm && ./setup"})
