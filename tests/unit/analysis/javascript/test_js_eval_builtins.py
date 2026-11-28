"""The built-ins and function shapes `JsEval.resolve` evaluates: string, array and buffer methods, decoder functions, arrows."""

from __future__ import annotations

import pytest

from cordon_scanner.analysis.javascript.evaluation.expressions import _Rewrites
from cordon_scanner.analysis.javascript.js_eval import JsEval

_LOOP = 'var s=""; for (var i=0;i<a.length;i++) s += String.fromCharCode(a[i]); return s;'


class TestStringMethods:
    @pytest.mark.parametrize(
        ("expr", "value"),
        [
            ('"hello".slice(1,3)', "el"),
            ('"hello".substring(2)', "llo"),
            ('"hello".substr(1,3)', "ell"),
            ('"hello".substr(1)', "ello"),
            ('"hello".replace("l","L")', "heLlo"),
            ('"hello".replaceAll("l","L")', "heLLo"),
            ('"HeLLo".toLowerCase()', "hello"),
            ('"HeLLo".toUpperCase().trim()', "HELLO"),
            ('" a ".trim()', "a"),
            ('"ab".concat(1, 2.0, 2.5)', "ab122.5"),
            ('"ab".concat("c", "d")', "abcd"),
            ('"abc".split("").join("-")', "a-b-c"),
            ('"a-b-c".split("-").reverse().join("+")', "c+b+a"),
            ('String.fromCharCode("hello".charCodeAt(1))', "e"),
        ],
    )
    def test_the_call_is_written_as_the_string_it_makes(self, expr: str, value: str) -> None:
        assert JsEval.resolve(f"require({expr});") == f'require("{value}");'

    def test_a_character_past_the_end_is_not_known(self) -> None:
        text = 'require(String.fromCharCode("a".charCodeAt(5)));'
        assert JsEval.resolve(text) == text

    def test_an_unknown_argument_leaves_a_hole_in_the_string(self) -> None:
        assert JsEval.resolve('x = "ab".concat(1, foo);') == 'x = "ab1_";'

    def test_an_unsupported_method_leaves_the_call(self) -> None:
        text = 'x = "a".foo();'
        assert JsEval.resolve(text) == text

    def test_a_replace_with_a_regex_is_not_evaluated(self) -> None:
        text = 'x = "hello".replace(/l/g, "L");'
        assert JsEval.resolve(text) == text

    @pytest.mark.xfail(
        strict=True, reason="a string argument that is a comma is read as the separator"
    )
    def test_a_comma_string_argument_splits(self) -> None:
        assert JsEval.resolve('x = "a,b".split(",").reverse().join("+");') == 'x = "b+a";'


class TestArrayMethods:
    def test_concat_joins_arrays_and_values(self) -> None:
        assert JsEval.resolve('x = ["a","b"].concat(["c"], "d").join("-");') == 'x = "a-b-c-d";'

    def test_slice_takes_the_tail(self) -> None:
        assert JsEval.resolve('x = ["a","b"].slice(1).join("");') == 'x = "b";'

    def test_slice_with_an_end(self) -> None:
        assert JsEval.resolve('x = ["a","b","c"].slice(0, 2).join("");') == 'x = "ab";'

    def test_an_unknown_element_leaves_a_hole(self) -> None:
        assert JsEval.resolve('x = ["a",foo].join("");') == 'x = "a_";'

    def test_a_mapped_arrow_runs_on_each_element(self) -> None:
        assert JsEval.resolve('x = ["a","b"].map(c => c + "!").join("-");') == 'x = "a!-b!";'

    def test_an_unsupported_method_leaves_the_call(self) -> None:
        text = 'x = ["a", "b"].sort();'
        assert JsEval.resolve(text) == text

    def test_a_number_array_is_not_a_string(self) -> None:
        text = "const x = [1,2,3].length;"
        assert JsEval.resolve(text) == text

    def test_an_element_by_index(self) -> None:
        assert JsEval.resolve('x = ["a","b"][1];') == 'x = "b";'

    def test_an_index_past_the_end_is_unknown(self) -> None:
        text = 'x = "a"[9];'
        assert JsEval.resolve(text) == text

    def test_a_member_named_by_a_computed_string(self) -> None:
        assert JsEval.resolve('x = ("a" + "b")["con" + "cat"]("c");') == 'x = "abc";'


class TestBuffersAndNumbers:
    @pytest.mark.parametrize(
        ("call", "value"),
        [
            ('Buffer.from("6162","hex").toString("hex")', "6162"),
            ('Buffer.from("6162","hex").toString("base64")', "YWI="),
            ('Buffer.from("6162","hex").toString("utf8")', "ab"),
            ('Buffer.from("YWJj","base64").toString()', "abc"),
            ('Buffer.from("YWJj","base64url").toString()', "abc"),
            ('Buffer.from("abc").toString()', "abc"),
            ("Buffer.from([104,105]).toString()", "hi"),
            ('Buffer.from("6162","hex")["toString"]()', "ab"),
            ('decodeURIComponent("%41%42")', "AB"),
            ('unescape("%41")', "A"),
            ('atob("YWJj")', "abc"),
            ("(255).toString(16)", "ff"),
            ("(5).toString(2)", "101"),
            ("(5).toString()", "5"),
            ('String.fromCharCode(parseInt("41", 16))', "A"),
        ],
    )
    def test_the_decoded_text_replaces_the_call(self, call: str, value: str) -> None:
        assert JsEval.resolve(f"x = {call};") == f'x = "{value}";'

    @pytest.mark.parametrize(
        "text",
        [
            'x = Buffer.from("zz","hex").toString();',
            "x = Buffer.from(5).toString();",
            'x = Buffer.from("6162","hex").foo();',
            'x = String.fromCharCode(parseInt("zz"));',
            "x = String.fromCharCode(foo);",
            "x = String.fromCharCode(-5);",
        ],
    )
    def test_what_cannot_be_decoded_stays_as_written(self, text: str) -> None:
        assert JsEval.resolve(text) == text

    def test_a_bad_base64_string_decodes_to_nothing_readable(self) -> None:
        assert JsEval.resolve('x = atob("!!!!");') == 'x = "";'


class TestArithmetic:
    @pytest.mark.parametrize(
        ("expr", "code"),
        [
            ("100 - 35", "A"),
            ("13 * 5", "A"),
            ("70 % 5 + 65", "A"),
            ("64 ^ 1", "A"),
            ("60 + 5", "A"),
            ("-(-65)", "A"),
        ],
    )
    def test_integer_arithmetic_feeds_a_character_code(self, expr: str, code: str) -> None:
        assert JsEval.resolve(f"x = String.fromCharCode({expr});") == f'x = "{code}";'

    def test_a_modulo_by_zero_is_unknown(self) -> None:
        text = "x = String.fromCharCode(5 % 0);"
        assert JsEval.resolve(text) == text

    def test_a_negated_string_is_unknown(self) -> None:
        text = 'x = -"a";'
        assert JsEval.resolve(text) == text

    def test_a_sum_of_numbers_and_a_string_joins_as_text(self) -> None:
        assert JsEval.resolve('x = 1 + 2 + "a";') == 'x = "3a";'

    def test_two_unknowns_stay_unknown(self) -> None:
        text = "x = foo + bar;"
        assert JsEval.resolve(text) == text

    def test_one_unknown_leaves_a_hole(self) -> None:
        assert JsEval.resolve('x = foo + "a";') == 'x = "_a";'


class TestDecoderFunctions:
    def test_a_loop_decoder_declared_as_a_function(self) -> None:
        text = f"function d(a){{ {_LOOP} }}\nrequire(d([111,115]));"
        assert JsEval.resolve(text).endswith('require("os");')

    def test_a_loop_decoder_given_a_string_returns_it(self) -> None:
        text = f'function d(a){{ {_LOOP} }}\nrequire(d("os"));'
        assert JsEval.resolve(text).endswith('require("os");')

    def test_a_loop_decoder_given_an_unknown_stays(self) -> None:
        text = f"function d(a){{ {_LOOP} }}\nrequire(d(foo));"
        assert JsEval.resolve(text).endswith("require(d(foo));")

    def test_a_loop_decoder_without_an_argument_stays(self) -> None:
        text = f"function d(a){{ {_LOOP} }}\nrequire(d());"
        assert JsEval.resolve(text).endswith("require(d());")

    def test_a_loop_decoder_as_an_arrow_with_a_block(self) -> None:
        text = f"const d = (a) => {{ {_LOOP} }};\nrequire(d([111,115]));"
        assert JsEval.resolve(text).endswith('require("os");')

    def test_a_loop_decoder_written_inside_a_map(self) -> None:
        text = f'require([[111],[115]].map((a) => {{ {_LOOP} }}).join(""));'
        assert JsEval.resolve(text) == 'require("os");'

    def test_a_function_with_a_constant_before_its_return(self) -> None:
        text = 'function f(x){ const k = "a"; return x + k; }\nrequire(f("b"));'
        assert JsEval.resolve(text).endswith('require("ba");')

    def test_a_function_with_only_a_return(self) -> None:
        text = 'function f(x){ return x + "z"; }\nrequire(f("b"));'
        assert JsEval.resolve(text).endswith('require("bz");')

    @pytest.mark.parametrize(
        "head",
        [
            "function f(x){ return; }",
            'function f(x){ return x + "z"',
            "function f(x){ foo(); return x; }",
            "function f(x){ const 1 = 2; return x; }",
            "function f(x){ " + " ".join(f"const a{n}={n};" for n in range(10)) + " return x; }",
        ],
    )
    def test_a_body_that_is_not_a_single_return_is_not_inlined(self, head: str) -> None:
        text = f'{head}\nrequire(f("b"));'
        assert JsEval.resolve(text).endswith('require(f("b"));')

    def test_a_function_without_a_parameter_list_is_ignored(self) -> None:
        assert JsEval.resolve('function f{ return 1; }\nrequire("a".concat("b"));').endswith(
            'require("ab");'
        )

    def test_an_arrow_with_a_block_return(self) -> None:
        text = 'const g = (x) => { return x + "q"; };\nrequire(g("p"));'
        assert JsEval.resolve(text).endswith('require("pq");')

    def test_an_arrow_with_a_block_that_is_not_a_return_stays(self) -> None:
        text = 'const g = (x) => { foo(x); };\nrequire(g("p"));'
        assert JsEval.resolve(text).endswith('require(g("p"));')

    def test_an_arrow_with_an_unclosed_block_stays(self) -> None:
        text = 'const g = (x) => { return x + "q"; ;\nrequire(g("p"));'
        assert JsEval.resolve(text).endswith('require(g("p"));')

    def test_an_arrow_with_a_default_parameter(self) -> None:
        text = 'const g = (x, y = "d") => x + y;\nrequire(g("p", "z"));'
        assert JsEval.resolve(text).endswith('require("pz");')

    def test_an_arrow_with_one_bare_parameter(self) -> None:
        assert JsEval.resolve('const g = x => x + "!";\nrequire(g("p"));').endswith(
            'require("p!");'
        )

    @pytest.mark.parametrize("head", ["const g = (x ! ) => x;", "const g = (x);", "const g = 5;"])
    def test_something_that_is_not_an_arrow_binds_no_function(self, head: str) -> None:
        text = f'{head}\nrequire(g("p"));'
        assert JsEval.resolve(text).endswith('require(g("p"));')


class TestBindings:
    def test_a_name_assigned_from_itself_accumulates(self) -> None:
        text = 'let s = "a"; s = s + "b"; s = s + "c"; require(s);'
        assert JsEval.resolve(text).endswith('require("abc");')

    def test_an_alias_of_require_is_called_as_require(self) -> None:
        text = 'const _r = require;\nconst m = _r("x" + "y");'
        assert 'const m = require("x" + "y");' in JsEval.resolve(text)

    def test_a_member_called_like_an_alias_is_not_one(self) -> None:
        text = 'const _r = require;\nconst m = obj._r("x");'
        assert JsEval.resolve(text) == text

    def test_a_constant_assembled_from_pieces_is_written_as_the_string(self) -> None:
        text = 'var cmd = get_ + tar_ + "x";\n'
        assert JsEval.resolve(text) == 'var cmd = "_x";\n'

    def test_an_assignment_to_a_member_is_not_a_binding(self) -> None:
        text = 'obj.a = "b"; require(a);'
        assert JsEval.resolve(text).endswith("require(a);")

    def test_spread_arguments_are_left_alone(self) -> None:
        text = 'x = f(...["a","b"]);'
        assert JsEval.resolve(text) == text

    def test_a_stray_closer_in_an_argument_list_stops_the_call(self) -> None:
        assert JsEval.resolve('x = "a".concat(]);') == 'x = "a_";'


class TestHolesAndLimits:
    def test_a_known_piece_is_kept_when_an_argument_is_a_partial_string(self) -> None:
        assert JsEval.resolve('x = "a".concat(foo + "x");') == 'x = "a_x";'

    def test_a_partial_string_can_be_extended(self) -> None:
        assert JsEval.resolve('x = (foo + "a").concat("b");') == 'x = "_ab";'

    def test_a_partial_string_has_no_other_methods(self) -> None:
        text = 'x = (foo + "a").slice(1);'
        assert JsEval.resolve(text) == text

    def test_a_bad_base64_length_is_not_decoded(self) -> None:
        text = 'x = atob("A");'
        assert JsEval.resolve(text) == text

    def test_a_built_in_it_does_not_model_is_left_alone(self) -> None:
        text = 'x = String.raw("a");'
        assert JsEval.resolve(text) == text

    def test_a_float_index_is_unknown(self) -> None:
        text = 'x = "ab"[1.5];'
        assert JsEval.resolve(text) == text

    def test_a_dot_with_no_member_leaves_the_chain(self) -> None:
        text = 'x = "a".concat("b").;'
        assert JsEval.resolve(text) == text

    def test_a_parameter_list_with_a_number_is_not_a_function(self) -> None:
        text = 'function f(x, 1){ return x; }\nrequire(f("b"));'
        assert JsEval.resolve(text).endswith('require(f("b"));')

    def test_nesting_past_the_depth_limit_gives_up(self) -> None:
        text = "x = " + "(" * 100 + '"a"' + ")" * 100 + '.concat("b");'
        assert JsEval.resolve(text) == text

    def test_a_call_nested_past_the_depth_limit_with_a_stray_closer_gives_up(self) -> None:
        text = "x = " + '"a".concat(' * 61 + "]" + ")" * 61 + ";"
        assert JsEval.resolve(text).startswith('x = "' + "a" * 61 + "_")

    def test_a_call_made_past_the_depth_limit_is_unknown(self) -> None:
        text = 'x = "z" + ' + "- " * 70 + '"a".concat("b");'
        assert JsEval.resolve(text) == 'x = "z_";'

    def test_a_string_past_the_size_limit_is_not_joined(self) -> None:
        text = 'x = "' + "a" * 15_000 + '" + "' + "b" * 15_000 + '";'
        assert JsEval.resolve(text) == text

    def test_an_array_past_the_element_limit_is_not_read(self) -> None:
        text = "x = [" + "1," * 20_001 + '].join("");'
        assert JsEval.resolve(text) == text

    def test_a_chain_past_the_step_limit_is_not_read(self) -> None:
        text = 'x = "a"' + ".trim()" * 25_000 + ";"
        assert JsEval.resolve(text) == text

    def test_a_map_past_the_step_limit_gives_up(self) -> None:
        text = "x = [" + "1," * 15_000 + '].map(c => c + "a").join("");'
        assert JsEval.resolve(text) == text

    def test_a_trailing_operator_has_no_right_side(self) -> None:
        text = 'x = "a" +'
        assert JsEval.resolve(text) == text

    def test_overlapping_edits_keep_the_first(self) -> None:
        assert _Rewrites._apply("abcdef", [(0, 3, "X"), (1, 2, "Y")]) == "Xdef"
