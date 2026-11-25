"""A JavaScript file that runs when a published package is loaded and that no reader can take to its end is a gap or is said, never silence.

The Python side has done this since 09 3a (`analysis/python/unparsed_source.py`): a running file that does not parse is a content gap when it
names anything that could run its pieces, and `SOURCE.BROKEN` (said) when it names nothing. A JavaScript entry file whose brackets do not
close was passed over without a word. Inert inputs written here: a package whose `main` is the file.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config

GAP = "OPERATIONAL.SOURCE.UNPARSED"
BROKEN = "OPERATIONAL.SOURCE.BROKEN"
RUNNING = "SUSPECT.SOURCE.UNPARSED_RUNNING.001"


class Package:
    """A package written for the test: scanned as a folder whose install hook runs the file, or as a published tarball whose `main` is it."""

    @staticmethod
    def manifest(main: str = "index.js", hook: bool = True) -> bytes:
        document = {"name": "x", "version": "1.0.0", "main": main}
        if hook:
            document["scripts"] = {"postinstall": f"node {main}"}
        return json.dumps(document).encode()

    @staticmethod
    def scan(folder: Path, files: dict[str, bytes], main: str = "index.js"):
        (folder / "package.json").write_bytes(Package.manifest(main))
        for name, body in files.items():
            target = folder / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
        return Scanner(Config.default().with_overrides(use_cache=False)).scan(folder)

    @staticmethod
    def scan_tarball(folder: Path, files: dict[str, bytes], main: str = "index.js"):
        path = folder / "x-1.0.0.tgz"
        with tarfile.open(path, "w:gz") as archive:
            for name, body in {"package.json": Package.manifest(main, hook=False), **files}.items():
                info = tarfile.TarInfo(f"package/{name}")
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
        return Scanner(Config.default().with_overrides(use_cache=False)).scan(path)

    @staticmethod
    def rules(result) -> set[str]:
        return {f.rule_id for f in result.active}


class TestAnEntryFileThatDoesNotClose:
    def test_with_an_act_in_it_is_a_gap_and_a_running_finding(self, tmp_path: Path) -> None:
        result = Package.scan_tarball(
            tmp_path, {"index.js": b"eval(atob('x'))\n" + b"function f( {\n" * 40}
        )
        assert result.content_complete is False
        assert GAP in {rule for rule, _ in result.content_gaps}
        assert RUNNING in Package.rules(result)

    def test_two_hundred_thousand_open_parentheses_with_nothing_to_act_is_said(
        self, tmp_path: Path
    ) -> None:
        result = Package.scan_tarball(tmp_path, {"index.js": b"(" * 200_000})
        assert BROKEN in Package.rules(result)
        assert GAP not in {rule for rule, _ in result.content_gaps}

    def test_two_hundred_thousand_open_brackets_with_an_act_is_a_gap(self, tmp_path: Path) -> None:
        result = Package.scan_tarball(
            tmp_path, {"index.js": b"require('child_process');" + b"[" * 200_000}
        )
        assert GAP in {rule for rule, _ in result.content_gaps}

    def test_a_close_of_the_wrong_kind_is_one_too(self, tmp_path: Path) -> None:
        result = Package.scan_tarball(
            tmp_path, {"index.js": b"fetch('https://h.invalid/a');\n" + b"const x = (1];\n" * 40}
        )
        assert GAP in {rule for rule, _ in result.content_gaps}

    def test_a_close_with_nothing_open_is_one_too(self, tmp_path: Path) -> None:
        result = Package.scan_tarball(tmp_path, {"index.js": b"eval('1');\n" + b"})\n" * 40})
        assert GAP in {rule for rule, _ in result.content_gaps}


class TestWhatIsLeftAlone:
    @pytest.mark.parametrize(
        "body",
        [
            b"module.exports = (a, b) => a + b;\n",
            b"const s = '(' + \"[\" ;\nconst r = /[(]/;\nconst t = `${s}(`;\nmodule.exports = [s, r, t];\n",
            b"// ( [ {\n/* ) ] } */\nmodule.exports = {};\n",
            b"const f = async function* () { yield `a${`b${1}`}`; };\nmodule.exports = f;\n",
            b"if (a) { b(); } else { c(); }\nlabel: for (;;) { break label; }\n",
        ],
    )
    def test_a_file_that_closes_every_bracket_is_not_reported(
        self, tmp_path: Path, body: bytes
    ) -> None:
        result = Package.scan(tmp_path, {"index.js": body})
        assert GAP not in {rule for rule, _ in result.content_gaps}
        assert not Package.rules(result) & {BROKEN, RUNNING}

    def test_a_file_nothing_runs_is_not_reported_however_broken(self, tmp_path: Path) -> None:
        result = Package.scan(
            tmp_path, {"index.js": b"module.exports = 1;\n", "unused.js": b"eval(" + b"(" * 50}
        )
        assert not Package.rules(result) & {BROKEN, RUNNING}
        assert GAP not in {rule for rule, _ in result.content_gaps}


class TestAPublishedPackagesMain:
    def test_a_main_that_does_not_close_and_names_an_act_is_a_gap(self, tmp_path: Path) -> None:
        result = Package.scan_tarball(
            tmp_path, {"index.js": b"eval(atob('x'));\n" + b"function f( {\n" * 40}
        )
        assert GAP in {rule for rule, _ in result.content_gaps}
        assert RUNNING in Package.rules(result)

    def test_a_main_that_does_not_close_and_names_nothing_is_said(self, tmp_path: Path) -> None:
        result = Package.scan_tarball(tmp_path, {"index.js": b"(" * 200_000})
        assert BROKEN in Package.rules(result)

    def test_a_main_that_closes_is_not_reported(self, tmp_path: Path) -> None:
        result = Package.scan_tarball(
            tmp_path, {"index.js": b"module.exports = (a, b) => a + b;\n"}
        )
        assert not Package.rules(result) & {BROKEN, RUNNING} and GAP not in {
            r for r, _ in result.content_gaps
        }


class Checkout:
    """A directory scan (a cloned repository, an MCP server checked out from git): the files `package.json` names are the files that run."""

    @staticmethod
    def scan(folder: Path, manifest: dict, files: dict[str, bytes]):
        (folder / "package.json").write_text(
            json.dumps({"name": "x", "version": "1.0.0", **manifest}), encoding="utf-8"
        )
        for name, body in files.items():
            target = folder / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
        return Scanner(Config.default().with_overrides(use_cache=False)).scan(folder)

    BAD = b"eval(atob('x'));\n" + b"function f( {\n" * 40


class TestADirectoryScan:
    @pytest.mark.parametrize(
        ("manifest", "name"),
        [
            ({"main": "lib/main.js"}, "lib/main.js"),
            ({}, "index.js"),
            ({"bin": "cli.js"}, "cli.js"),
            ({"bin": {"x": "bin/x.js", "y": "bin/y.js"}}, "bin/y.js"),
            ({"exports": "./entry.js"}, "entry.js"),
            ({"exports": {".": {"import": "./esm.mjs", "require": "./cjs.cjs"}}}, "esm.mjs"),
            ({"scripts": {"postinstall": "node setup.js"}}, "setup.js"),
            ({"scripts": {"preinstall": "node --no-warnings ./pre.js && echo done"}}, "pre.js"),
        ],
    )
    def test_a_file_package_json_names_runs_and_a_broken_one_is_a_gap(
        self, tmp_path: Path, manifest: dict, name: str
    ) -> None:
        result = Checkout.scan(tmp_path, manifest, {name: Checkout.BAD})
        assert GAP in {rule for rule, _ in result.content_gaps}, name
        assert RUNNING in Package.rules(result)

    def test_a_file_a_running_file_requires_runs_too(self, tmp_path: Path) -> None:
        files = {
            "index.js": b"const a = require('./lib/a');\nmodule.exports = a;\n",
            "lib/a.js": b"module.exports = require('./b.js');\n",
            "lib/b.js": Checkout.BAD,
        }
        result = Checkout.scan(tmp_path, {}, files)
        assert GAP in {rule for rule, _ in result.content_gaps}

    def test_a_file_nothing_names_does_not_run(self, tmp_path: Path) -> None:
        result = Checkout.scan(
            tmp_path,
            {"main": "index.js"},
            {
                "index.js": b"module.exports = 1;\n",
                "other.js": Checkout.BAD,
                "test/t.js": Checkout.BAD,
            },
        )
        assert not Package.rules(result) & {BROKEN, RUNNING}
        assert GAP not in {rule for rule, _ in result.content_gaps}

    @pytest.mark.parametrize(
        "text", [b"{not json", b"[]", b'{"main": 5, "bin": [1], "scripts": "x", "exports": 7}']
    )
    def test_a_manifest_that_is_not_one_is_no_crash_and_names_nothing(
        self, tmp_path: Path, text: bytes
    ) -> None:
        (tmp_path / "package.json").write_bytes(text)
        (tmp_path / "other.js").write_bytes(Checkout.BAD)
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        assert GAP not in {
            rule for rule, _ in result.content_gaps
        }  # no manifest names other.js: it does not run

    def test_a_balanced_main_is_not_reported(self, tmp_path: Path) -> None:
        result = Checkout.scan(
            tmp_path, {"main": "m.js"}, {"m.js": b"module.exports = () => ({ a: [1, 2] });\n"}
        )
        assert not Package.rules(result) & {BROKEN, RUNNING}


class TestWhatTheReaderGetsWrongItself:
    """The tokenizer is not a parser: a regular expression holding a bracket, a text in JSX, a type argument puts it off by a few brackets. A file off by
    fewer than 52 is read as source; the boundary is pinned on both sides."""

    @pytest.mark.parametrize(
        ("errors", "reported"), [(1, False), (51, False), (52, True), (53, True)]
    )
    def test_the_boundary_is_fifty_two_errors(
        self, tmp_path: Path, errors: int, reported: bool
    ) -> None:
        result = Package.scan_tarball(
            tmp_path, {"index.js": b"eval(atob('x'));\n" + b")\n" * errors}
        )
        assert (GAP in {rule for rule, _ in result.content_gaps}) is reported

    @staticmethod
    def file_of(errors: int, kilobytes: int) -> bytes:
        """A file that acts and has `errors` wrong closes, padded with comment lines to exactly `kilobytes` KB."""
        head = b"eval(atob('x'));\n" + b")\n" * errors
        room = kilobytes * 1024 - len(head)
        lines, rest = divmod(max(room, 0), 64)
        return (
            head
            + (b"//" + b"x" * 61 + b"\n") * lines
            + (b"//" + b"x" * (rest - 3) + b"\n" if rest >= 3 else b"")
        )

    @pytest.mark.parametrize(
        ("errors", "kilobytes", "reported"),
        [
            (60, 0, True),  # small and broken: over the floor
            (60, 300, True),  # 300 KB allows only the floor (52): density 0.1 would be 30
            (
                99,
                1000,
                False,
            ),  # 1,000 KB allows 100: a big file the tokenizer slips on, as the legitimate ones do
            (100, 1000, True),  # the allowance is fewer than 100
            (85, 1787, False),  # the worst legitimate file measured
            (5000, 1000, True),  # hostile: thousands of wrong closes in a big file
            (5000, 3000, True),
            (500, 100, True),
        ],
    )
    def test_the_allowance_grows_with_the_size_at_a_tenth_of_an_error_per_kb(
        self, tmp_path: Path, errors: int, kilobytes: int, reported: bool
    ) -> None:
        result = Package.scan_tarball(tmp_path, {"index.js": self.file_of(errors, kilobytes)})
        assert (GAP in {rule for rule, _ in result.content_gaps}) is reported

    def test_the_allowance_is_the_floor_for_a_small_file_and_a_tenth_per_kb_above(self) -> None:
        from cordon_scanner.analysis.javascript.unparsed_source import JsUnparsed

        assert [
            JsUnparsed.allowed(size)
            for size in (0, 1024, 100_000, 512 * 1024, 521_000, 1024 * 1024, 2 * 1024 * 1024)
        ] == [52, 52, 52, 52, 52, 103, 205]

    def test_a_stray_close_in_a_file_that_acts_is_left_alone(self, tmp_path: Path) -> None:
        result = Package.scan_tarball(
            tmp_path, {"index.js": b"const cp = require('child_process');\ncp.exec('ls');\n)\n"}
        )
        assert GAP not in {rule for rule, _ in result.content_gaps}
        assert not Package.rules(result) & {BROKEN, RUNNING}

    def test_the_count_recovers_after_a_wrong_close(self) -> None:
        from cordon_scanner.analysis.javascript.js_eval import JsEval
        from cordon_scanner.analysis.javascript.unparsed_source import JsUnparsed

        assert (
            JsUnparsed.errors(JsEval.tokens("(a]", templates=True)) == 2
        )  # the open is skipped, the wrong close is one more
        assert JsUnparsed.errors(JsEval.tokens("a)", templates=True)) == 1
        assert JsUnparsed.errors(JsEval.tokens("((", templates=True)) == 2
        assert JsUnparsed.errors(JsEval.tokens("([{}])", templates=True)) == 0
