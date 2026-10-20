"""Static evaluation of the names and strings a JavaScript file computes (`detect/js_eval.py`)."""

from __future__ import annotations

import time

from cordon_scanner.analysis.javascript.js_eval import JsEval
from cordon_scanner.analysis.javascript.js_fold import JsFold


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


class TestRegexLiterals:
    def test_brackets_inside_a_pattern_do_not_unbalance_the_file(self) -> None:
        text = "const re = /[(]+/g;\nconst u = String.fromCharCode(104, 105);\n"
        assert '"hi"' in JsEval.resolve(text)

    def test_division_is_not_a_pattern(self) -> None:
        kinds = [t.kind for t in JsEval.tokens("x = a / b / c;")]
        assert "regex" not in kinds

    def test_a_pattern_after_return_and_after_an_operator(self) -> None:
        kinds = [
            t.kind
            for t in JsEval.tokens("function f(s) { return /a\\/b/.test(s) || s.split(/,/); }")
        ]
        assert kinds.count("regex") == 2


class TestBounds:
    def test_a_long_escaped_string_is_read_once(self) -> None:
        # A documentation site's search index: `JSON.parse("...")` of half a megabyte with an
        # escaped quote every few characters. Giving up at the length cap and resuming one character
        # later re-read the string from every quote inside it (review 98: two minutes for one file).
        body = '\\"k\\":\\"v\\",' * 12_000
        text = f'window.searchData = JSON.parse("{body}");\n'
        started = time.monotonic()
        tokens = JsEval.tokens(text)
        assert time.monotonic() - started < 5
        assert [t.kind for t in tokens].count("longstr") == 1

    def test_an_unterminated_quote_ends_at_its_line(self) -> None:
        text = 'x = a \' b\ny = "ok";\n'
        assert [t.value for t in JsEval.tokens(text) if t.kind == "str"] == ["ok"]

    def test_nested_template_literals_do_not_index_past_the_end(self) -> None:
        # A logger's format line (review 98): the evaluation gave up at the end of the tokens and
        # the rewrite indexed one past them.
        text = (
            "    `${color(String(event.status), statusColor)} ${color(`+${formatLatency(event.latency)}`, "
            '"magenta")} ` + color(`requestId=${event.requestId}`, "dim")\n'
            "  return `${Math.round(latency * 100) / 100}ms`;\n"
        )
        assert JsEval.resolve(text).count("\n") == text.count("\n")

    def test_a_recursive_helper_with_a_callback_argument_terminates(self) -> None:
        # Compiled TypeScript (`__awaiter`): evaluating the call re-entered the body, met the
        # callback's closing brace where an argument should be, and read it forever (review 98).
        text = (
            "function convert(definition, top, cache = {}) {\n"
            "    return __awaiter(this, void 0, void 0, function* () {\n"
            "        schema.extra = yield convert(definition.values, false);\n"
            "        }\n"
            "    }\n"
            "    return convert(definition, true);\n"
            "}\n"
        )
        assert JsEval.resolve(text).count("\n") == text.count("\n")

    def test_an_unterminated_string_does_not_hang(self) -> None:
        text = '"' + "a" * 200_000
        assert JsEval.resolve(text) is not None

    def test_ordinary_code_is_unchanged(self) -> None:
        text = "function add(a, b) { return a + b; }\nmodule.exports = add;\n"
        assert JsEval.resolve(text) == text


class TestModuleNames:
    def test_a_module_under_a_borrowed_name_is_read_as_the_module(self) -> None:
        text = 'var mint = require("vm");\nmint.runInContext(body, ctx);\n'
        assert "vm.runInContext(body, ctx)" in JsEval.module_names(text)

    def test_a_name_bound_twice_is_left_alone(self) -> None:
        text = (
            'var a = require("vm");\nfunction f() { var a = require("fs"); a.readFileSync(x); }\n'
        )
        assert JsEval.module_names(text) == text

    def test_a_name_reassigned_is_left_alone(self) -> None:
        text = 'let c = require("child_process");\nc = other;\nc.exec(x);\n'
        assert JsEval.module_names(text) == text
