"""Code a package runs without writing it as code (review 98).

Two shapes no rule read: a program carried as a long string literal and handed to `Function` from
an install hook, and a library's function that executes what a server sends it. Neither decodes
anything, so the decode-and-run composites never saw them.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.detect.code.capability.javascript import JavaScriptCapabilities
from cordon_scanner.foundation.config import Config
from cordon_scanner.foundation.content import FileContent

STRING_CODE = "SUSPECT.INSTALL.STRING_CODE.001"
REMOTE_CODE = "SUSPECT.DROPPER.REMOTE_CODE.001"
#: A thousand-odd characters of harmless JavaScript, the size of a program and not its behaviour.
PROGRAM = "var a=[" + ",".join(str(i) for i in range(400)) + "];"


class Package:
    @staticmethod
    def npm(tmp_path: Path, files: dict[str, str], scripts: dict[str, str] | None = None) -> Path:
        manifest = {"name": "demo", "version": "1.0.0", "main": "index.js"}
        if scripts:
            manifest["scripts"] = scripts
        members = {"package/package.json": json.dumps(manifest)}
        members.update({f"package/{name}": text for name, text in files.items()})
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, text in members.items():
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        target = tmp_path / "demo-1.0.0.tgz"
        target.write_bytes(buffer.getvalue())
        return target

    @staticmethod
    def rules(target: Path) -> set[str]:
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(target)
        return {f.rule_id for f in result.findings}


class TestAStringRunAsCode:
    @staticmethod
    def hit(text: str) -> bool:
        raw = text.encode()
        content = FileContent(path="x.js", raw=raw, size=len(raw))
        return bool(JavaScriptCapabilities.js_string_code_run(content, "javascript"))

    def test_function_over_a_long_literal_after_its_parameter_names(self):
        assert self.hit(f'Function("w", "r", "{PROGRAM}")({{}});\n')

    def test_eval_and_vm_over_a_long_literal(self):
        assert self.hit(f"eval('{PROGRAM}');\n")
        assert self.hit(f"require('vm').runInThisContext(`{PROGRAM}`);\n")

    def test_a_short_or_computed_string_is_not(self):
        assert not self.hit('new Function("return this")();\n' + "// " + PROGRAM + "\n")
        assert not self.hit("eval(`" + PROGRAM + "${tail}`);\n")
        assert not self.hit("eval(source);\nconst s = '" + PROGRAM + "';\n")

    def test_a_literal_filled_by_a_replace_is_still_carried(self):
        # A placeholder the replacement fills does not make the literal computed: the program is
        # still the literal (`.replace(/X/g, "")` would excuse any payload).
        assert self.hit(f'new Function(`{PROGRAM}/*X*/`.replace(/X/g, ""));\n')

    def test_run_from_an_install_hook_it_is_reported(self, tmp_path):
        target = Package.npm(
            tmp_path,
            {"test/check.js": f'Function("w", "{PROGRAM}")({{}});\n', "index.js": ""},
            {"postinstall": "node test/check.js"},
        )
        assert STRING_CODE in Package.rules(target)

    def test_in_library_code_nothing_runs_at_install(self, tmp_path):
        target = Package.npm(tmp_path, {"index.js": f'module.exports = Function("{PROGRAM}");\n'})
        assert STRING_CODE not in Package.rules(target)


class TestWhatAServerSends:
    def test_a_command_read_from_a_response_and_executed(self, tmp_path):
        library = (
            "const { exec } = require('child_process');\n"
            "const axios = require('axios');\n"
            "async function initialize(address) {\n"
            "  const response = await axios.get(address);\n"
            "  const { command } = response.data;\n"
            "  if (command) exec(command, () => {});\n"
            "}\n"
            "module.exports = { initialize };\n"
        )
        assert REMOTE_CODE in Package.rules(Package.npm(tmp_path, {"index.js": library}))

    def test_a_response_that_is_only_parsed_is_not(self, tmp_path):
        library = (
            "const axios = require('axios');\n"
            "const { execFile } = require('child_process');\n"
            "async function version(address) {\n"
            "  const response = await axios.get(address);\n"
            "  return response.data.version;\n"
            "}\n"
            "function open(file) { execFile('xdg-open', [file]); }\n"
            "module.exports = { version, open };\n"
        )
        assert REMOTE_CODE not in Package.rules(Package.npm(tmp_path, {"index.js": library}))


class TestLongTextIsReadToTheEnd:
    def test_text_past_the_limit_is_scored_in_windows_that_cover_it(self):
        from cordon_scanner.detect.agents.mcp_model import MAX_SKILL_TEXT, SKILL_MODEL

        text = "a" * (MAX_SKILL_TEXT * 2 + 17)
        windows = SKILL_MODEL.windows(text)
        assert len(windows) > 1
        assert all(len(w) <= MAX_SKILL_TEXT for w in windows)
        assert SKILL_MODEL.windows_unread(text) == 0
        assert windows[-1].endswith(text[-100:])

    def test_a_short_text_is_one_window(self):
        from cordon_scanner.detect.agents.mcp_model import SKILL_MODEL

        assert SKILL_MODEL.windows("short") == ["short"]


class TestASkillsClaim:
    def test_front_matter_is_read_as_what_the_skill_says_it_does(self):
        from cordon_scanner.decide.verdict import VerdictFeatures

        skill = (
            b"---\nname: csv-tidy\ndescription: Format CSV files and fix column names.\n---\nBody\n"
        )
        features = VerdictFeatures.package(
            [("skills/csv-tidy/SKILL.md", len(skill))], {"skills/csv-tidy/SKILL.md": skill}
        )
        assert features["skill_front_matter"] == 1.0
        assert features["skill_claims_files"] == 1.0
        assert features["skill_claims_network"] == 0.0
