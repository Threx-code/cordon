"""Static evaluation of the names and strings a JavaScript file computes (`detect/js_eval.py`)."""

from __future__ import annotations

from cordon_scanner.detect.js_eval import JsEval
from cordon_scanner.detect.js_fold import JsFold


class TestResolve:
    def test_a_hex_decoder_behind_an_alias_of_require(self) -> None:
        text = (
            'const _d = h => Buffer.from(h, "hex").toString();\n'
            "const _r = require;\n"
            'const m = _r(_d("6f73"));\n'
        )
        assert 'require("os")' in JsEval.resolve(text)

    def test_character_codes_mapped_and_joined(self) -> None:
        text = "const u = [104,116,116,112,115,58,47,47,120,46,105,110].map(c => String.fromCharCode(c)).join('');\n"
        assert '"https://x.in"' in JsEval.resolve(text)

    def test_a_property_named_by_concatenation(self) -> None:
        text = 'const os = require("os"); const h = os["host" + "name"]();\n'
        # As the scanner reads it: literal fragments joined first (`js_fold`), then evaluated.
        assert "os.hostname()" in JsEval.resolve(JsFold.fold(text))

    def test_a_constant_passed_as_an_argument(self) -> None:
        text = 'const domain = "probe.example.invalid";\ndns.lookup(domain, cb);\n'
        assert 'dns.lookup("probe.example.invalid", cb)' in JsEval.resolve(text)

    def test_decoding_is_reported_on_its_line(self) -> None:
        text = 'const x = 1;\nexec(Buffer.from("6375726c2068747470733a2f2f612e636f6d", "hex").toString());\n'
        view, lines = JsEval.resolve_with_decodes(text)
        assert "curl https://a.com" in view and lines == [2]

    def test_lines_stay_where_they_were(self) -> None:
        text = 'const a = "x"\n  + "y";\nfoo();\n'
        assert JsEval.resolve(text).count("\n") == text.count("\n")


class TestBounds:
    def test_an_unterminated_string_does_not_hang(self) -> None:
        text = '"' + "a" * 200_000
        assert JsEval.resolve(text) is not None

    def test_ordinary_code_is_unchanged(self) -> None:
        text = "function add(a, b) { return a + b; }\nmodule.exports = add;\n"
        assert JsEval.resolve(text) == text
