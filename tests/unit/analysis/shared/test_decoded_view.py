"""`DecodedView`: one decoded reading of a file and its map back to the raw text (note 18). Code-only
fixtures: names, paths and calls, nothing that runs."""

from __future__ import annotations

import pytest

from cordon_scanner.analysis.shared.decoded_view import DecodedView, ViewOverBudget, _FString


class Spell:
    @staticmethod
    def fullwidth(word: str) -> str:
        return "".join(chr(ord(c) + 0xFEE0) if c.isascii() and c.isalpha() else c for c in word)


class TestAPythonView:
    @staticmethod
    def view(text: str) -> DecodedView:
        return DecodedView.of(text, "python")

    def test_a_file_with_nothing_to_decode_is_its_text(self) -> None:
        text = "import os\nPATH = '~/.config/app'  # a comment\nprint(PATH)\n"
        v = self.view(text)
        assert not v.differs and v.text == text and not v.partial

    def test_escapes_in_a_literal_are_written_as_their_characters(self) -> None:
        v = self.view("p = '\\x2e\\x62ashrc'\nq = \"\\N{FULL STOP}ssh/id\\u005frsa\"\n")
        assert "'.bashrc'" in v.text
        assert '".ssh/id_rsa"' in v.text
        assert v.text.count("\n") == 2

    def test_adjacent_literals_are_joined_and_keep_their_lines(self) -> None:
        text = "x = (\n    'cr'\n    'on'  # split\n    'tab'\n)\ny = 1\n"
        v = self.view(text)
        assert "'crontab'" in v.text
        assert v.text.count("\n") == text.count("\n")
        assert v.text.splitlines()[-1] == "y = 1"

    def test_a_backslash_newline_inside_a_literal_keeps_the_line_count(self) -> None:
        text = "s = 'ab\\\ncd\\x41'\nz = 2\n"
        v = self.view(text)
        assert v.text.count("\n") == text.count("\n")
        assert v.text.splitlines()[-1] == "z = 2"

    def test_names_are_read_nfkc_normalised(self) -> None:
        v = self.view(f"{Spell.fullwidth('subprocess')}.{Spell.fullwidth('run')}(c)\n")
        assert v.text == "subprocess.run(c)\n"

    def test_raw_strings_and_bytes(self) -> None:
        assert not self.view("r = r'\\x41'\n").differs  # a raw literal holds no escape
        assert "'Bin'" in self.view("b = b'\\x42in'\n").text

    def test_an_fstring_has_its_literal_parts_decoded_and_its_fields_kept(self) -> None:
        v = self.view("f = f'\\x2e{name!r:>{w}}/\\x63ron{{x}}'\n")
        assert v.text == "f = f'.{name!r:>{w}}/cron{{x}}'\n"

    def test_the_fstring_split_is_our_own(self) -> None:
        """The same split of the f-string's source on every Python: up to 3.11 it is one STRING
        token, from 3.12 the tokenizer splits it; ours reads the whole span either way."""
        prefix, quote, parts = _FString.split("rf'''a{b['k']}c{{d}}'''") or ("", "", [])
        assert (prefix, quote) == ("rf", "'''")
        assert parts == [("lit", "a"), ("field", "{b['k']}"), ("lit", "c{d}")]
        assert _FString.decoded("f'{x}'") is None  # nothing to re-spell

    def test_a_file_tokenize_stops_on_keeps_the_view_before_it(self) -> None:
        v = self.view("a = '\\x41'\nb = (\n")
        assert v.partial
        assert v.text.startswith("a = 'A'\n")

    def test_positions_map_back_to_the_raw_text(self) -> None:
        raw = "x = '\\x63rontab' + y\n"
        v = self.view(raw)
        start = v.text.index("crontab")
        rs, re_ = v.to_raw(start, start + len("crontab"))
        assert raw[rs:re_] == "'\\x63rontab'"
        after = v.text.index("+ y")
        assert raw[slice(*v.to_raw(after, after + 3))] == "+ y"

    def test_past_its_budget_the_view_is_refused(self, monkeypatch) -> None:
        monkeypatch.setattr(DecodedView, "MAX_TOKENS", 50)
        with pytest.raises(ViewOverBudget):
            DecodedView.of("x = 1\n" * 100, "python")
        monkeypatch.setattr(DecodedView, "MAX_CHARS", 10)
        with pytest.raises(ViewOverBudget):
            DecodedView.of("y = 2\n" * 10, "javascript")


class TestAScriptView:
    @staticmethod
    def view(text: str) -> DecodedView:
        return DecodedView.of(text, "javascript")

    def test_identifier_and_string_escapes_are_decoded(self) -> None:
        v = self.view('const m = \\u0072equire("\\x63hild_process");\n\\u{66}etch(u);\n')
        assert v.text == 'const m = require("child_process");\nfetch(u);\n'

    def test_other_escapes_and_comments_stay_as_written(self) -> None:
        text = 'a = "line\\nbreak";\n// \\u0072equire\n/* \\x41 */\n'
        v = self.view(text)
        assert v.text == text

    def test_a_regex_literal_is_left_alone(self) -> None:
        text = "x = /\\u0041[/]b/g.test(s);\n"
        assert self.view(text).text == text

    def test_template_literals_and_their_expressions(self) -> None:
        v = self.view("t = `\\x2e/${ {a: '\\x62'}.a }/\\u0063`;\n")
        assert v.text == "t = `./${ {a: 'b'}.a }/c`;\n"

    def test_an_escaped_backslash_is_not_an_escape(self) -> None:
        text = "s = '\\\\x41';\n"
        assert self.view(text).text == text

    def test_a_script_without_a_backslash_is_its_text(self) -> None:
        assert not self.view("require('./x');\n").differs

    def test_another_language_is_its_text(self) -> None:
        assert not DecodedView.of("echo \\x41\n", "shell").differs
