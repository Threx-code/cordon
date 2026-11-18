"""An install hook's shape says what the scan could not read (reviews/mcp-98/47-INSTALL-HOOK-SHAPE.md).

Two shapes of consumer-time hook (`preinstall`, `install`, `postinstall`) of a package the scanner
was handed, as opposed to the scanned project's own, are install-time code the content detectors
cannot be trusted with:

* the program is carried inline (`node -e '...'`), outside any file a reviewer opens, and a program
  that does nothing the capability rules label is exactly the one that read as harmless;
* the command hands an interpreter a script the scan does not hold, so the code that runs is unread.

Both block on their own. What does not change: a hook that loads a file of the package (graded as
that file), a package-manager guard, an author-time hook, the project's own manifest.
"""

from __future__ import annotations

import io
import json
import subprocess
import tarfile
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.decide.policy import PolicyGate
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.models import Confidence, Severity

INLINE = "SUSPECT.INSTALL.INLINE_PROGRAM.001"
UNREAD = "SUSPECT.INSTALL.UNREAD.001"
SCRIPT = "SUSPECT.INSTALL.SCRIPT.001"


class HookKit:
    @staticmethod
    def package(tmp_path: Path, scripts: dict[str, str], **extra: str) -> Path:
        manifest = json.dumps({"name": "demo-pkg", "version": "1.0.0", "scripts": scripts})
        files = {"package/package.json": manifest, "package/index.js": "module.exports = 1;\n"}
        files.update({f"package/{name}": text for name, text in extra.items()})
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for member, text in files.items():
                data = text.encode()
                info = tarfile.TarInfo(member)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        target = tmp_path / "demo-pkg-1.0.0.tgz"
        target.write_bytes(buffer.getvalue())
        return target

    @staticmethod
    def scan(target: Path):
        return Scanner(Config.default().with_overrides(use_cache=False)).scan(target)

    @staticmethod
    def result(tmp_path: Path, scripts: dict[str, str], **extra: str):
        return HookKit.scan(HookKit.package(tmp_path, scripts, **extra))

    @staticmethod
    def own_project(tmp_path: Path, scripts: dict[str, str]):
        """The scanned project's own manifest: the scan target is a git root."""
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "p", "version": "1.0.0", "scripts": scripts}), encoding="utf-8"
        )
        subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
        return Scanner().scan(tmp_path)

    @staticmethod
    def rules(result) -> set[str]:
        return {f.rule_id for f in result.findings}

    @staticmethod
    def blocks(result) -> bool:
        return not PolicyGate.evaluate(result, Config.default().policy).passed


class TestAnInlineProgramInAConsumerHook:
    @pytest.mark.parametrize(
        "hook",
        [
            {"postinstall": "node -e \"console.log('thanks for installing')\""},
            {"preinstall": "python3 -c 'print(1)'"},
            {"install": 'node -e "process.exit(0)"'},
            {"postinstall": 'node -e "var x = 1 + 1; console.log(x)" && echo done'},
        ],
    )
    def test_it_is_reported_and_blocks(self, tmp_path: Path, hook: dict[str, str]) -> None:
        result = HookKit.result(tmp_path, hook)
        found = [f for f in result.findings if f.rule_id == INLINE]
        assert found, "a program carried inline in an install hook is a finding by itself"
        assert all(f.severity >= Severity.HIGH and f.confidence >= Confidence.MEDIUM for f in found)
        assert HookKit.blocks(result)

    def test_the_finding_names_the_hook_and_the_manifest(self, tmp_path: Path) -> None:
        result = HookKit.result(tmp_path, {"postinstall": "node -e \"console.log('x')\""})
        found = next(f for f in result.findings if f.rule_id == INLINE)
        assert found.location.path.endswith("package/package.json")
        assert "postinstall" in found.message

    def test_the_install_script_finding_stays(self, tmp_path: Path) -> None:
        result = HookKit.result(tmp_path, {"postinstall": "node -e \"console.log('x')\""})
        assert SCRIPT in HookKit.rules(result)

    @pytest.mark.parametrize("name", ["prepare", "prepublishOnly", "prepack", "postpublish"])
    def test_an_author_time_hook_is_not(self, tmp_path: Path, name: str) -> None:
        result = HookKit.result(tmp_path, {name: "node -e \"console.log('x')\""})
        assert INLINE not in HookKit.rules(result)

    def test_a_program_that_only_loads_a_file_of_the_package_is_graded_as_that_file(
        self, tmp_path: Path
    ) -> None:
        hook = {"postinstall": "node -e \"try{require('./setup.js')}catch(e){}\""}
        result = HookKit.result(tmp_path, hook, **{"setup.js": "module.exports = 1;\n"})
        assert INLINE not in HookKit.rules(result)
        assert UNREAD not in HookKit.rules(result)
        assert not HookKit.blocks(result)

    def test_a_loader_of_a_file_the_scan_does_not_hold_is_unread_code(self, tmp_path: Path) -> None:
        hook = {"postinstall": "node -e \"try{require('./setup.js')}catch(e){}\""}
        result = HookKit.result(tmp_path, hook)
        assert UNREAD in HookKit.rules(result)
        assert HookKit.blocks(result)

    def test_a_package_manager_guard_is_a_recognised_idiom(self, tmp_path: Path) -> None:
        guard = (
            "node -e \"if(process.env.npm_execpath.indexOf('yarn') === -1) "
            "throw new Error('install with yarn')\""
        )
        result = HookKit.result(tmp_path, {"preinstall": guard})
        assert INLINE not in HookKit.rules(result)

    def test_a_guard_that_also_does_something_else_is_not(self, tmp_path: Path) -> None:
        program = (
            "node -e \"if(process.env.npm_execpath.indexOf('yarn') === -1) "
            "throw 1; require('https').get('https://example.invalid/x')\""
        )
        result = HookKit.result(tmp_path, {"preinstall": program})
        assert INLINE in HookKit.rules(result)

    def test_the_scanned_projects_own_manifest_is_not_blocked_for_it(self, tmp_path: Path) -> None:
        result = HookKit.own_project(tmp_path, {"postinstall": "node -e \"console.log('x')\""})
        assert INLINE not in HookKit.rules(result)


class TestAHookThatRunsAFileTheScanDoesNotHold:
    @pytest.mark.parametrize(
        "hook",
        [
            {"postinstall": "node scripts/setup.js"},
            {"postinstall": "node ./lib/run.js --quiet"},
            {"install": "sh ./missing.sh"},
            {"preinstall": "python3 helper.py"},
            {"postinstall": "node scripts/setup.js || true"},
        ],
    )
    def test_it_is_unread_install_time_code_and_blocks(
        self, tmp_path: Path, hook: dict[str, str]
    ) -> None:
        result = HookKit.result(tmp_path, hook)
        found = [f for f in result.findings if f.rule_id == UNREAD]
        assert found
        assert all(f.severity >= Severity.HIGH and f.confidence >= Confidence.MEDIUM for f in found)
        assert HookKit.blocks(result)

    def test_the_finding_says_why_the_reach_is_incomplete(self, tmp_path: Path) -> None:
        result = HookKit.result(tmp_path, {"postinstall": "node scripts/setup.js"})
        found = next(f for f in result.findings if f.rule_id == UNREAD)
        assert "install_reach_incomplete" in found.message
        assert "scripts/setup.js" in found.message

    def test_a_file_the_scan_holds_is_read_as_install_code_instead(self, tmp_path: Path) -> None:
        result = HookKit.result(
            tmp_path,
            {"postinstall": "node scripts/setup.js"},
            **{"scripts/setup.js": "module.exports = 1;\n"},
        )
        assert UNREAD not in HookKit.rules(result)

    @pytest.mark.parametrize(
        "hook",
        [
            {"postinstall": "node-gyp rebuild"},
            {"postinstall": "npm run build", "build": "tsc"},
            {"postinstall": "python -m pip install requests"},
            {"postinstall": "node --version"},
            {"postinstall": "node ./node_modules/.bin/patch-package"},
        ],
    )
    def test_a_tool_a_flag_or_a_dependency_path_is_not(
        self, tmp_path: Path, hook: dict[str, str]
    ) -> None:
        assert UNREAD not in HookKit.rules(HookKit.result(tmp_path, hook))

    @pytest.mark.parametrize("name", ["prepare", "prepublishOnly"])
    def test_an_author_time_hook_is_not(self, tmp_path: Path, name: str) -> None:
        assert UNREAD not in HookKit.rules(HookKit.result(tmp_path, {name: "node missing.js"}))

    def test_the_scanned_projects_own_manifest_is_not_blocked_for_it(self, tmp_path: Path) -> None:
        result = HookKit.own_project(tmp_path, {"postinstall": "node scripts/setup.js"})
        assert UNREAD not in HookKit.rules(result)
