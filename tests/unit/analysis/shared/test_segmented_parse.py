"""A large file parsed whole a statement at a time finds the calls a whole parse finds, in place."""

from __future__ import annotations

import pytest

from cordon_scanner.analysis.shared import ast_providers
from cordon_scanner.analysis.shared.segmented_parse import Segments, SegmentView, WholeFileCalls
from cordon_scanner.foundation.files.windows import BytesWindows

BODY = (
    'const cp = require("child_process");\n'
    'function run(cmd) { cp.exec("sh -c " + cmd); return fetch("https://example.invalid/x"); }\n'
    'const s = "a;b;c}d"; run(s); setTimeout(() => { cp.spawn("id", ["-u"]); }, 10);\n'
)


class Parsed:
    @staticmethod
    def js() -> ast_providers.AstProvider:
        provider = ast_providers.AstProviders.ast_provider_for("javascript")
        assert provider is not None
        return provider

    @staticmethod
    def whole(text: str) -> list[tuple[str, int, int, tuple[str, ...]]]:
        return sorted(
            (c.name, c.line, c.column, c.arguments) for c in Parsed.js().resolve_calls(text)
        )

    @staticmethod
    def segmented(text: str) -> list[tuple[str, int, int, tuple[str, ...]]]:
        data = text.encode()

        def read(offset: int, length: int) -> bytes:
            return data[offset : offset + length]

        parts = (
            (s.start, s.line, s.column, SegmentView(read, s)) for s in Segments.of(read, len(data))
        )
        located = Parsed.js().resolve_parts(parts)  # type: ignore[attr-defined]
        return sorted((c.name, c.line, c.column, c.arguments) for _, c in located)


class Small:
    @pytest.fixture
    def small(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Segments, "SIZE", 300)
        monkeypatch.setattr(Segments, "TAIL", 150)


class TestSegmented(Small):
    @pytest.mark.usefixtures("small")
    def test_many_lines_give_the_calls_of_a_whole_parse(self) -> None:
        text = BODY * 12
        assert Parsed.segmented(text) == Parsed.whole(text)

    @pytest.mark.usefixtures("small")
    def test_one_long_line_gives_the_calls_of_a_whole_parse(self) -> None:
        text = BODY.replace("\n", " ") * 12
        assert Parsed.segmented(text) == Parsed.whole(text)

    @pytest.mark.usefixtures("small")
    def test_no_cut_falls_inside_a_string(self) -> None:
        data = (BODY.replace("\n", " ") * 12).encode()
        tokens = __import__(
            "cordon_scanner.analysis.javascript.js_eval", fromlist=["JsEval"]
        ).JsEval
        strings = [
            (t.start, t.end)
            for t in tokens.tokens(data.decode(), templates=True)
            if t.kind == "str"
        ]
        cuts = [s.end for s in Segments.of(lambda o, n: data[o : o + n], len(data))][:-1]
        assert cuts
        assert not any(a < cut < b for cut in cuts for a, b in strings)

    @pytest.mark.usefixtures("small")
    def test_no_cut_falls_inside_a_template(self) -> None:
        text = "log(`step ${n}; done ${f(`inner; ${m}`)}`); " * 40
        cuts = [s.end for s in Segments.of(lambda o, n: text.encode()[o : o + n], len(text))][:-1]
        assert cuts
        assert all(text[cut - 2 : cut] == "; " or text[cut - 1] == ";" for cut in cuts)

    def test_a_template_heavy_text_is_read_in_one_pass(self) -> None:
        text = "x = `a${`b${`c${d}`}`}`;\n" * 200_000  # 5 MB of nested templates
        started = __import__("time").monotonic()
        Segments._statement_ends(text, len(text) - Segments.TAIL)
        assert __import__("time").monotonic() - started < 10

    @pytest.mark.usefixtures("small")
    def test_a_literal_longer_than_a_segment_is_read_past(self) -> None:
        text = 'const blob = "' + "A" * 5000 + '";\n' + BODY
        assert Parsed.segmented(text) == Parsed.whole(text)

    @pytest.mark.usefixtures("small")
    def test_an_alias_declared_later_governs_an_earlier_call(self) -> None:
        text = "cp.exec(x);\n" + "f(1);\n" * 80 + 'const cp = require("child_process");\n'
        assert ("child_process.exec", 1, 0, ("",)) in Parsed.segmented(text)


class TestPieces(Small):
    @pytest.mark.usefixtures("small")
    def test_a_window_takes_its_own_calls_at_its_own_lines(self) -> None:
        data = (BODY * 12).encode()
        source = BytesWindows(data)
        begin = data.index(b"\n", 900) + 1
        piece = data[begin : begin + 500]
        calls = WholeFileCalls.view(Parsed.js(), source, begin, piece)
        assert calls
        for call in calls:
            at = piece.split(b"\n")[call.line - 1][call.column :]
            assert at.startswith((call.name.split(".")[0].encode(), b"cp."))
        assert len(calls) < len(Parsed.whole(data.decode()))

    def test_a_piece_that_is_not_the_files_bytes_is_left_to_its_own_parse(self) -> None:
        source = BytesWindows(BODY.encode())
        assert WholeFileCalls.view(Parsed.js(), source, 0, b"something else") is None
