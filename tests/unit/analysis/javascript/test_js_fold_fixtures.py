"""SI-V5: each constant fold of the JavaScript value reading has a fixture: string literals, concatenation, templates without substitutions,
simple variables bound once (`JsValues`: the strings an argument can spell) and `String.fromCharCode` and array `join` (`JsEval`: the
resolved view of the file). A spelling the file does not decide gives no set at all."""

from __future__ import annotations

import pytest
from test_js_values import values

from cordon_scanner.analysis.javascript.js_eval import JsEval
from cordon_scanner.analysis.javascript.js_fold import JsFold


class TestEachValueFoldHasAFixture:
    FIXTURES = (
        ("a string literal", 'use("cmd");'),
        ("a concatenation", 'use("c" + "m" + "d");'),
        ("a template without substitutions", "use(`cmd`);"),
        ("a variable bound once", 'const name = "cmd";\nuse(name);'),
        (
            "a variable bound once to a concatenation",
            'const a = "c";\nconst name = a + "md";\nuse(name);',
        ),
    )

    @pytest.mark.parametrize(("fold", "source"), FIXTURES, ids=[f[0] for f in FIXTURES])
    def test_the_argument_spells_the_one_string(self, fold: str, source: str) -> None:
        assert values(source) == {"cmd"}, fold


class TestEachSpellingFoldHasAFixture:
    FIXTURES = (
        ("String.fromCharCode", "run(String.fromCharCode(99, 109, 100));"),
        ("an array join", 'run(["c", "m", "d"].join(""));'),
        (
            "character codes mapped and joined",
            "run([99, 109, 100].map(c => String.fromCharCode(c)).join(''));",
        ),
        ("fragments of a name", 'run("c" + "md");'),
    )

    @pytest.mark.parametrize(("fold", "source"), FIXTURES, ids=[f[0] for f in FIXTURES])
    def test_the_resolved_view_shows_the_one_string(self, fold: str, source: str) -> None:
        assert 'run("cmd")' in JsEval.resolve(JsFold.fold(source)), fold


class TestWhatTheFileDoesNotDecideIsNotFolded:
    def test_a_template_with_a_value_the_file_does_not_know(self) -> None:
        assert values("use(`cmd_${suffix}`);") is None

    def test_a_concatenation_with_a_parameter(self) -> None:
        assert values('function f(p) { use("cmd" + p); }') is None

    def test_a_character_code_the_file_does_not_know_is_left_as_written(self) -> None:
        assert 'run("cmd")' not in JsEval.resolve(
            JsFold.fold("run(String.fromCharCode(99, code));")
        )
