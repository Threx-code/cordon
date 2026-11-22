"""Bidi controls in bundled strings, as against Trojan Source (review 98, FP-7).

The control is written at run time from an escape, so this file does not itself carry one.
"""

from __future__ import annotations

from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.models import Severity

RLO = "‮"  # U+202E RIGHT-TO-LEFT OVERRIDE -- the Trojan Source primitive
LRE = "‪"  # LEFT-TO-RIGHT EMBEDDING (opener)
PDF = "‬"  # POP DIRECTIONAL FORMATTING (closes an embedding)
RLI = "⁧"  # RIGHT-TO-LEFT ISOLATE (opener)
PDI = "⁩"  # POP DIRECTIONAL ISOLATE (closes an isolate)
RLE = "\u202b"  # RIGHT-TO-LEFT EMBEDDING (opener)
LRO = "\u202d"  # LEFT-TO-RIGHT OVERRIDE
FSI = "\u2068"  # FIRST STRONG ISOLATE (opener)


class BidiKit:
    @staticmethod
    def severities(tmp_path: Path, path: str, text: str) -> set[Severity]:
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        config = Config.default().with_overrides(use_cache=False, severity_threshold=Severity.INFO)
        result = Scanner(config).scan(tmp_path)
        return {f.severity for f in result.findings if f.rule_id == "SUSPECT.OBFUSCATION.BIDI.001"}


class TestBidi:
    def test_in_a_bundled_string_it_is_display_data(self, tmp_path: Path) -> None:
        found = BidiKit.severities(tmp_path, "static/js/katex.min.js", f'var dir="{RLO}";\n')
        assert found == {Severity.INFO}

    def test_in_hand_written_source_it_stays_high(self, tmp_path: Path) -> None:
        found = BidiKit.severities(tmp_path, "src/app.js", f'var role = "user{RLO} // admin";\n')
        assert found == {Severity.HIGH}

    def test_in_a_bundled_comment_it_is_not_demoted(self, tmp_path: Path) -> None:
        # Generated output keeps its existing ceiling (MEDIUM); only a string is display data.
        found = BidiKit.severities(tmp_path, "dist/app.js", f"/* {RLO} */ var a = 1;\n")
        assert found and all(s > Severity.INFO for s in found)

    def test_a_balanced_inert_embedding_in_a_literal_is_display_data(self, tmp_path: Path) -> None:
        # census D: a phone number wrapped in LRE..PDF inside a string literal, in hand-written
        # source, is an iOS-style display label -- it reorders only its own digits, not the code.
        found = BidiKit.severities(tmp_path, "src/fmt.py", f"label = '{LRE}158 8020 6986{PDF}'\n")
        assert found == {Severity.INFO}, found

    def test_a_stretched_string_that_holds_its_quote_stays_high(self, tmp_path: Path) -> None:
        # Trojan Source stretched-string variant (CVE-2021-42574): the span carries the literal's own
        # closing quote, so what follows it re-reads as code. Code delimiters alone (a paren and a
        # semicolon) inside the literal do not: a balanced pair reorders only its own contents.
        text = f'cmd = "run{RLI}"); drop(){PDI}safe"\n'
        assert BidiKit.severities(tmp_path, "src/app.py", text) == {Severity.HIGH}

    def test_an_override_anywhere_keeps_a_balanced_embedding_high(self, tmp_path: Path) -> None:
        # Even a balanced inert embedding stays high if the file also carries an override: the
        # override is the attack primitive, and its presence is not excused by display data.
        text = f"label = '{LRE}158 8020{PDF}'\nrole = \"user{RLO} // admin\"\n"
        found = BidiKit.severities(tmp_path, "src/app.py", text)
        assert Severity.HIGH in found, found


class TestARangeTable:
    """A control written as a bound in a table of codepoints (QUALITY-DAYS item 1: KaTeX's tokenizer ranges
    and Infragistics' locale ranges blocked two packages). Only controls that cannot reverse
    left-to-right text, and only when every control in the file is one."""

    def test_a_left_to_right_embedding_as_a_range_bound_is_data(self, tmp_path: Path) -> None:
        table = f"var r = /[\u2000-\u2027{LRE}-\ud7ff\uf900-\uffff]/;\n"
        assert BidiKit.severities(tmp_path, "src/tok.js", table) == {Severity.INFO}

    def test_a_pop_isolate_as_a_range_bound_is_data(self, tmp_path: Path) -> None:
        table = f'var unassigned = "\u1ff5\u1fff\u2065-{PDI}\u2072\u2073";\n'
        assert BidiKit.severities(tmp_path, "src/locale.js", table) == {Severity.INFO}

    def test_a_right_to_left_isolate_as_a_range_bound_stays_high(self, tmp_path: Path) -> None:
        table = f'var r = "\u2065-{RLI}\u2072";\n'
        assert BidiKit.severities(tmp_path, "src/locale.js", table) == {Severity.HIGH}

    def test_a_table_first_does_not_lower_an_override_later(self, tmp_path: Path) -> None:
        text = f'var r = /[\u2027{LRE}-\ud7ff]/;\nvar role = "user{RLO} // admin";\n'
        assert BidiKit.severities(tmp_path, "src/app.js", text) == {Severity.HIGH}

    def test_a_control_beside_ascii_is_not_a_table(self, tmp_path: Path) -> None:
        assert BidiKit.severities(tmp_path, "src/app.js", f"var a = x-{LRE}y;\n") == {Severity.HIGH}


class TestABalancedEmbeddingInsideOneString:
    """E1 (reviews/pypi-98/23): an embedding or isolate opened and popped inside one string literal, whose
    span holds nothing that can end the literal or the line, reorders nothing outside the literal. Every
    directional control of the file has to be accounted for; an override never is."""

    def test_brackets_and_punctuation_in_the_span_are_display_data(self, tmp_path: Path) -> None:
        text = f"label = '{LRE}Tokyo (JP) - main{PDF}'\n"
        assert BidiKit.severities(tmp_path, "src/fmt.py", text) == {Severity.INFO}

    def test_a_json_string_with_a_wrapped_name_is_display_data(self, tmp_path: Path) -> None:
        text = f'{{"name": "{LRE}Alias (old){PDF}", "id": 4}}\n'
        assert BidiKit.severities(tmp_path, "data/names.json", text) == {Severity.INFO}

    def test_an_isolate_pair_in_a_string_is_display_data(self, tmp_path: Path) -> None:
        text = f'label = "{FSI}name (x){PDI}"\n'
        assert BidiKit.severities(tmp_path, "src/fmt.py", text) == {Severity.INFO}

    # The twins: each is a shape that can reorder what a reviewer reads, and each keeps the finding.
    def test_an_override_around_the_text_stays_high(self, tmp_path: Path) -> None:
        for opener in (RLO, LRO):
            text = f"label = '{opener}Tokyo (JP){PDF}'\n"
            assert BidiKit.severities(tmp_path, "src/fmt.py", text) == {Severity.HIGH}

    def test_a_span_holding_the_closing_quote_is_the_stretched_string(self, tmp_path: Path) -> None:
        text = f"x = 'a{LRE}b' + c{PDF}'\n"
        assert BidiKit.severities(tmp_path, "src/fmt.py", text) == {Severity.HIGH}

    def test_a_span_holding_a_brace_or_a_backslash_stays_high(self, tmp_path: Path) -> None:
        for span in ("a{b", "a}b", "{x}", "a\\b"):
            text = f'x = "{LRE}{span}{PDF}"\n'
            assert BidiKit.severities(tmp_path, "src/fmt.py", text) == {Severity.HIGH}, span

    def test_an_fstring_expression_or_template_literal_in_the_span_stays_high(
        self, tmp_path: Path
    ) -> None:
        fstring = f"x = f'{LRE}{{payload()}}{PDF}'\n"
        assert BidiKit.severities(tmp_path, "src/fmt.py", fstring) == {Severity.HIGH}
        template = f"var x = `{LRE}${{payload()}}{PDF}`;\n"
        assert BidiKit.severities(tmp_path, "src/app.js", template) == {Severity.HIGH}

    def test_an_embedding_in_a_comment_stays_high(self, tmp_path: Path) -> None:
        text = f"value = 1  # {LRE}ok (fine){PDF}\nif admin:\n    pass\n"
        assert BidiKit.severities(tmp_path, "src/fmt.py", text) == {Severity.HIGH}

    def test_an_embedding_in_an_identifier_stays_high(self, tmp_path: Path) -> None:
        text = f"is{LRE}Admin = 1\nx = 2{PDF}\n"
        assert BidiKit.severities(tmp_path, "src/fmt.py", text) == {Severity.HIGH}

    def test_an_opener_never_popped_stays_high(self, tmp_path: Path) -> None:
        text = f"label = 'a{LRE}b (c)'\n"
        assert BidiKit.severities(tmp_path, "src/fmt.py", text) == {Severity.HIGH}

    def test_a_harmless_first_pair_does_not_lower_a_later_opener(self, tmp_path: Path) -> None:
        text = f"a = '{LRE}ok (fine){PDF}'\nb = 'x{RLE}y'\n"
        assert BidiKit.severities(tmp_path, "src/fmt.py", text) == {Severity.HIGH}

    def test_a_mismatched_pop_stays_high(self, tmp_path: Path) -> None:
        text = f"label = '{LRE}Tokyo (JP){PDI}'\n"
        assert BidiKit.severities(tmp_path, "src/fmt.py", text) == {Severity.HIGH}


class TestAPopThatClosesNothing:
    """E2: a PDF or PDI with no opener earlier in its paragraph pops nothing, so it reorders nothing
    (the bidi algorithm's own rule). One that does close an earlier opener keeps the normal reading."""

    def test_a_lone_pdf_in_a_string(self, tmp_path: Path) -> None:
        text = f"msg = 'ok{PDF} fine'\n"
        assert BidiKit.severities(tmp_path, "src/fmt.py", text) == {Severity.INFO}

    def test_a_lone_pdi_in_a_string(self, tmp_path: Path) -> None:
        text = f"msg = 'ok{PDI} fine'\n"
        assert BidiKit.severities(tmp_path, "src/fmt.py", text) == {Severity.INFO}

    def test_a_pop_on_the_next_line_does_not_close_an_earlier_opener(self, tmp_path: Path) -> None:
        # An opener's effect ends with its paragraph, so the pop on the next line closes nothing; the
        # opener itself is the unpopped one and keeps the finding.
        text = f"a = 'x{LRE}y'\nb = 'z{PDF}'\n"
        assert BidiKit.severities(tmp_path, "src/fmt.py", text) == {Severity.HIGH}

    def test_a_pop_that_closes_an_earlier_opener_keeps_the_reading(self, tmp_path: Path) -> None:
        text = f"x = '{LRE}ab'; y = 1{PDF}\n"
        assert BidiKit.severities(tmp_path, "src/fmt.py", text) == {Severity.HIGH}


class TestSpanContentThatIsJustText:
    """Once an embedding is balanced inside one literal, with no enclosing quote, backslash, brace or newline in
    its span, nothing outside the span is affected: punctuation in it is text (reviews/pypi-98/23)."""

    def test_punctuation_in_the_span_is_text(self, tmp_path: Path) -> None:
        for span in ("a=b", "a;b", "a<b", "a>b", "a//b", "a#b", "a/*b", "a--b", "( ;x; )", "#Tag"):
            text = f'x = "{LRE}{span}{PDF}"\n'
            assert BidiKit.severities(tmp_path, "src/fmt.py", text) == {Severity.INFO}, span

    def test_a_semicolon_delimited_emoticon_and_a_hashtag_in_json(self, tmp_path: Path) -> None:
        emoticon = f"label = '{LRE}( ;x; ){PDF}'\n"
        assert BidiKit.severities(tmp_path, "src/fmt.py", emoticon) == {Severity.INFO}
        hashtag = f'{{"tag": "{LRE}#Name{PDF}"}}\n'
        assert BidiKit.severities(tmp_path, "data/tags.json", hashtag) == {Severity.INFO}

    def test_an_entity_for_a_quote_is_text(self, tmp_path: Path) -> None:
        text = f"label = '{LRE}&quot;x&#39;{PDF}'\n"
        assert BidiKit.severities(tmp_path, "src/fmt.py", text) == {Severity.INFO}
