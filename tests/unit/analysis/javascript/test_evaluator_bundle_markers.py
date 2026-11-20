"""The JavaScript evaluator (computed names and hosts written out) runs on any file that is not a bundle, whatever its size.

A file over 100,000 bytes counted as a bundle by its size alone, and over 100,000 characters the evaluator did not run at all, so padding a
script past that switched off the folding of its computed names. A bundle is now a file that carries a bundler's marks: a `dist/` or
`.min` path, a bundler's opening, lines too long to have been written. Inert text: a few lines and comment padding, never run.
"""

from __future__ import annotations

import pytest

from cordon_scanner.analysis.javascript.js_eval import JsEval
from cordon_scanner.detect.code.capability.build_output import BuildOutput
from cordon_scanner.detect.code.capability.javascript import JavaScriptCapabilities
from cordon_scanner.detect.code.capability.labelling import Labelling
from cordon_scanner.detect.code.obfuscation.packing import BUNDLER_PRELUDE
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import WHOLE_FILE_BYTES
from kits.padding import Padding

#: A computed name: the marker the evaluator looks for.
CODE = "const name = String.fromCharCode(99, 112);\nrun(name);\n"
WEBPACK = "/******/ (function(modules) { var __webpack_require__ = 1; })\n"


class Kit:
    @staticmethod
    def evaluated(monkeypatch: pytest.MonkeyPatch, path: str, text: str) -> bool:
        """Whether the evaluator was given the file."""
        calls: list[str] = []

        def record(folded: str) -> tuple[str, list[int]]:
            calls.append(folded)
            return folded, []

        monkeypatch.setattr(JsEval, "resolve_with_decodes", staticmethod(record))
        content = FileContent.from_bytes(path, text.encode())
        Labelling.folded_capabilities(content, (), "javascript", [])
        return bool(calls)


class TestTheEvaluatorsReach:
    def test_it_is_the_whole_file_size(self) -> None:
        assert JavaScriptCapabilities.JS_EVAL_MAX_BYTES == WHOLE_FILE_BYTES

    def test_a_small_script_is_evaluated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert Kit.evaluated(monkeypatch, "index.js", CODE)

    @pytest.mark.parametrize("before", [150_000, 1_500_000, 5_000_000])
    def test_a_large_script_that_is_no_bundle_is_evaluated(
        self, monkeypatch: pytest.MonkeyPatch, before: int
    ) -> None:
        assert Kit.evaluated(monkeypatch, "index.js", Padding.lines(before) + CODE)


class TestWhatCountsAsABundle:
    def test_a_bundlers_opening_does(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert not Kit.evaluated(monkeypatch, "index.js", WEBPACK + Padding.lines(150_000) + CODE)

    def test_a_dist_path_does(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert not Kit.evaluated(monkeypatch, "dist/index.js", Padding.lines(150_000) + CODE)

    def test_a_min_name_does(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert not Kit.evaluated(monkeypatch, "lib/app.min.js", CODE)

    def test_lines_too_long_to_have_been_written_do(self, monkeypatch: pytest.MonkeyPatch) -> None:
        minified = "var a=1;" * 1_000 + CODE.replace("\n", "")
        assert BuildOutput.is_minified(FileContent.from_bytes("index.js", minified.encode()))
        assert not Kit.evaluated(monkeypatch, "index.js", minified)

    def test_size_alone_does_not(self) -> None:
        big = FileContent.from_bytes("index.js", (Padding.lines(200_000) + CODE).encode())
        assert not BuildOutput.bundled(big)

    def test_the_bundler_opening_is_the_one_the_long_line_rule_trusts(self) -> None:
        assert BuildOutput.BUNDLER_HEAD.pattern == BUNDLER_PRELUDE.pattern
