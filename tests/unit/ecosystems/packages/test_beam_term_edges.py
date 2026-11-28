"""The Elixir and Erlang term reader: every refusal and every expression it keeps whole (`ecosystems/packages/hex.py`)."""

from __future__ import annotations

import pytest

from cordon_scanner.ecosystems.packages.hex import (
    Atom,
    BeamTerms,
    HexEcosystem,
    Opaque,
    TermError,
)
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits
from cordon_scanner.foundation.models import Scope


class TestRefusals:
    @pytest.mark.parametrize(
        ("text", "why"),
        [
            ("@", "malformed module attribute"),
            ("@1x", "malformed module attribute"),
            ("~", "malformed sigil"),
            ("~~", "malformed sigil"),
            ("~w", "malformed sigil"),
            ("~w?a b?", "malformed sigil"),
            ("~w(a b", "a sigil is never closed"),
            ('~s"""\nabc', "a sigil is never closed"),
            ("[a: (1", "unexpected character"),
        ],
    )
    def test_a_malformed_term_is_refused_with_its_reason(self, text: str, why: str) -> None:
        with pytest.raises(TermError, match=why):
            BeamTerms.parse(text)

    def test_an_erlang_term_followed_by_more_text_is_refused(self) -> None:
        with pytest.raises(TermError, match="text after the term"):
            BeamTerms.parse('{a, "x\\"y"}.', erlang=True)


class TestValues:
    def test_nil_is_none_and_an_escaped_quote_stays_in_the_string(self) -> None:
        assert BeamTerms.parse("nil") is None
        assert BeamTerms.parse('"a\\"b"') == 'a"b'

    def test_a_sigil_with_angle_brackets_is_kept_as_written(self) -> None:
        assert BeamTerms.parse("~w<a b>") == Opaque("~w<a b>")

    @pytest.mark.parametrize(
        "expression",
        [
            "&(&1 + 1)",
            "fn x -> x end",
            "fn -> ~w(x) end",
            "if x do 1 # c\n else 2 end",
        ],
    )
    def test_an_expression_the_reader_cannot_evaluate_is_kept_whole_as_text(
        self, expression: str
    ) -> None:
        [(key, value)] = BeamTerms.parse(f"[dep: {expression}]")
        assert key == Atom("dep")
        assert isinstance(value, Opaque)
        assert value.text.replace("\n", " ").startswith(expression.split()[0])


class _Kit:
    @staticmethod
    def fc(path: str, text: str) -> FileContent:
        return FileContent.from_bytes(path, text.encode("utf-8"), Limits())

    @staticmethod
    def adapter() -> HexEcosystem:
        return EcosystemRegistry.BY_ID["hex"]  # type: ignore[return-value]


class TestRebarConfig:
    CONFIG = (
        '{deps, [{foo, "1.0"}, bar, 3, {baz, {pkg, other}}, {qux, {pkg, other2, "2.0"}},\n'
        '        {gitdep, {git, "https://example.invalid/g", {tag, "v1"}}}]}.\n'
    )

    def test_each_shape_of_a_dependency_names_the_package_and_the_range_it_asks_for(self) -> None:
        manifest = _Kit.adapter().parse_manifest(_Kit.fc("rebar.config", self.CONFIG))
        seen = {d.name: d.spec for d in manifest.dependencies}
        assert seen == {
            "foo": "1.0",
            "bar": "*",
            "other": "*",
            "other2": "2.0",
            "gitdep": "git+https://example.invalid/g#v1",
        }
        assert any(d.field_name == "deps (as baz)" for d in manifest.dependencies)


class TestRebarLock:
    def parse(self, text: str):
        return _Kit.adapter().parse_lockfile(_Kit.fc("rebar.lock", text))

    def test_an_empty_file_has_no_lock_term(self) -> None:
        assert self.parse("").parse_error == "no lock term"

    def test_a_lock_whose_second_part_is_not_a_list_is_refused(self) -> None:
        assert self.parse('{"1.2.0", notalist}.\n').parse_error == "no list of locked dependencies"

    def test_entries_that_are_not_well_formed_are_skipped_not_guessed(self) -> None:
        text = (
            '{"1.2.0", [{<<"good">>, {pkg, <<"good">>, <<"1.0.0">>}, 0}, atom_entry, '
            '{<<"short">>, x}, {<<"odd">>, notasource, 0}]}.\n'
            '"text".\n'
            '[{pkg_hash_ext, [{<<"good">>, <<"ABCD">>}]}].\n'
        )
        graph = self.parse(text)
        assert not graph.parse_error
        assert [(e.name, e.integrity is not None, e.direct) for e in graph.entries] == [
            ("good", True, True)
        ]


class TestMix:
    def test_a_lock_that_is_not_a_map_is_refused(self) -> None:
        graph = _Kit.adapter().parse_lockfile(_Kit.fc("mix.lock", '"just a string"'))
        assert graph.parse_error == "not a mix.lock map"

    def test_a_lock_entry_that_is_not_a_tuple_is_skipped(self) -> None:
        graph = _Kit.adapter().parse_lockfile(_Kit.fc("mix.lock", '%{"a": "text", "b": nil}'))
        assert graph.entries == ()
        assert graph.parse_error is None

    def test_a_project_with_no_list_after_its_deps_function_declares_nothing(self) -> None:
        text = "defmodule M do\n  def project do\n    1\n  end\nend\n"
        manifest = _Kit.adapter().parse_manifest(_Kit.fc("mix.exs", text))
        assert manifest.dependencies == ()

    def test_a_runtime_false_dependency_is_a_build_dependency(self) -> None:
        text = (
            "defmodule M do\n  defp deps do\n"
            '    [{:tool, "~> 1.0", runtime: false}, {:lib, "~> 2.0"}]\n  end\nend\n'
        )
        manifest = _Kit.adapter().parse_manifest(_Kit.fc("mix.exs", text))
        assert {d.name: d.scope for d in manifest.dependencies} == {
            "tool": Scope.BUILD,
            "lib": Scope.RUNTIME,
        }

    def test_a_native_compiler_in_the_project_is_a_build_hook(self) -> None:
        text = (
            "defmodule M do\n  def project do\n"
            "    [app: :m, compilers: [:elixir_make, :other]]\n  end\n"
            "  defp deps, do: []\nend\n"
        )
        manifest = _Kit.adapter().parse_manifest(_Kit.fc("mix.exs", text))
        assert [h.name for h in manifest.hooks] == ["compiler elixir_make"]

    def test_a_hex_release_names_its_metadata_config(self) -> None:
        pattern = _Kit.adapter().release_manifest()
        assert pattern is not None
        assert pattern.search("jason-1.4.4.tar!metadata.config")
        assert not pattern.search("other.config")


class TestKeptWhole:
    @pytest.mark.parametrize(
        "expression",
        [
            "fn -> 1 # why\n end",
            "fn -> fn -> 1 end end",
            "fn -> if x, do: 1 end",
            "fn -> if x do 1 end end",
            '&String.starts_with?(&1, "test/")',
            '"a" <> "b"',
        ],
    )
    def test_a_function_or_a_call_that_holds_blocks_comments_and_strings_is_read_to_its_own_end(
        self, expression: str
    ) -> None:
        [(key, value), (second, last)] = BeamTerms.parse(f"[a: {expression}, b: 2]")
        assert (key, second, last) == (Atom("a"), Atom("b"), 2)
        assert isinstance(value, Opaque)

    def test_a_map_keeps_string_keys_and_atom_keys(self) -> None:
        assert BeamTerms.parse('%{"k" => 1, j: 2}') == {"k": 1, "j": 2}

    def test_a_block_that_never_ends_is_refused(self) -> None:
        with pytest.raises(TermError, match="never closed with `end`"):
            BeamTerms.parse("[a: fn -> 1, b: 2]")


class TestLimitsAndShapes:
    def test_an_interpolated_string_is_code_not_data(self) -> None:
        with pytest.raises(TermError, match="interpolated string is code"):
            BeamTerms.parse('"a #{b}"')

    def test_nesting_and_term_counts_past_their_limits_are_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(BeamTerms, "MAX_DEPTH", 2)
        with pytest.raises(TermError, match="nested deeper than 2"):
            BeamTerms.parse("[[[[1]]]]")
        monkeypatch.setattr(BeamTerms, "MAX_DEPTH", 64)
        monkeypatch.setattr(BeamTerms, "MAX_ITEMS", 3)
        with pytest.raises(TermError, match="more than 3 terms"):
            BeamTerms.parse("[1, 2, 3, 4, 5]")

    def test_an_erlang_quoted_atom_is_an_atom(self) -> None:
        assert BeamTerms.consult("'a b'.") == [Atom("a b")]

    def test_a_colon_with_no_atom_after_it_is_refused(self) -> None:
        with pytest.raises(TermError, match="malformed atom"):
            BeamTerms.parse("[:1]")

    def test_a_capture_with_nothing_to_capture_is_refused(self) -> None:
        with pytest.raises(TermError, match="malformed function capture"):
            BeamTerms.parse("[a: &]")

    def test_a_call_that_never_closes_is_refused(self) -> None:
        with pytest.raises(TermError, match="never closed"):
            BeamTerms.parse("[a: foo(1, 2]")

    def test_commas_inside_nested_brackets_do_not_split_the_value(self) -> None:
        [(_, first), (_, second)] = BeamTerms.parse("[a: foo(1, (2, 3)), b: 4]")
        assert isinstance(first, Opaque) and first.text == "foo(1, (2, 3))"
        assert second == 4

    def test_an_improper_list_is_kept_as_unread_text_not_as_data(self) -> None:
        assert BeamTerms.parse("[1, 2 | 3]") == [1, Opaque("2 | 3")]

    def test_an_operator_then_brackets_after_a_term_are_read_to_the_end_of_the_value(self) -> None:
        [(_, value), (_, after)] = BeamTerms.parse("[a: 1 + (2), b: 3]")
        assert value == Opaque("1 + (2)") and after == 3


class TestInlineAndReleaseForms:
    def test_a_deps_list_written_beside_a_project_that_calls_a_function_for_it_is_found(
        self,
    ) -> None:
        text = (
            "defmodule M do\n  def project do\n    [app: :m, deps: deps()]\n  end\n"
            '  def more do\n    [deps: [{:a, "~> 1.0"}]]\n  end\nend\n'
        )
        manifest = _Kit.adapter().parse_manifest(_Kit.fc("mix.exs", text))
        assert [(d.name, d.spec) for d in manifest.dependencies] == [("a", "~> 1.0")]

    def test_a_hex_release_is_named_by_the_name_and_version_in_its_metadata_config(self) -> None:
        adapter = _Kit.adapter()
        text = '{<<"name">>,<<"jason">>}.\n{<<"version">>,<<"1.4.4">>}.\n'
        found = adapter.release_manifest().search("jason-1.4.4.tar!metadata.config")
        assert adapter.release_identity("jason-1.4.4.tar!metadata.config", text, found) == (
            "jason",
            "1.4.4",
        )
        assert (
            adapter.release_identity("x!metadata.config", '{<<"name">>,<<"a">>}.\n', found) is None
        )
