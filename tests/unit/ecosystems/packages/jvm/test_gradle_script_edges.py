"""The edges of the Gradle script reader: strings that hide comment marks, structure that is cut
short, and the version catalog's less common shapes.

A script damaged or cut short must be reported by line, never read as one that declares nothing.
"""

from __future__ import annotations

import pytest

from cordon_scanner.ecosystems.packages.jvm.gradle_scripts import (
    GradleCatalog,
    GradleReader,
    GradleScript,
    GradleValues,
)


class TestCommentsAndStrings:
    def test_a_comment_mark_inside_a_string_is_not_a_comment(self) -> None:
        text = "a = \"http://x.example\"\nb = 'it\\'s // here'\n"
        assert GradleScript.without_comments(text) == text

    def test_a_triple_quoted_string_keeps_its_comment_marks_and_a_real_comment_is_blanked(
        self,
    ) -> None:
        text = 'x = """\n// kept\n"""\n// gone\n/* a\nb */ y = 1\n'
        out = GradleScript.without_comments(text)
        assert "// kept" in out
        assert "gone" not in out
        assert out.count("\n") == text.count("\n")
        assert out.rstrip().endswith("y = 1")

    def test_a_block_comment_that_never_ends_blanks_the_rest(self) -> None:
        out = GradleScript.without_comments("a = 1\n/* open\nstill")
        assert out.startswith("a = 1\n")
        assert "open" not in out
        assert "still" not in out

    def test_a_triple_quoted_string_may_hold_braces(self) -> None:
        statements = GradleScript("x = '''{ not a block }'''\n").statements()
        assert [s.closure for s in statements] == [None]
        assert "not a block" in statements[0].text

    def test_a_single_quoted_string_with_an_escaped_quote_ends_at_the_real_one(self) -> None:
        statements = GradleScript("x = 'a\\'}'\ny = 2\n").statements()
        assert [s.text for s in statements] == ["x = 'a\\'}'", "y = 2"]


class TestStructureThatBreaks:
    @pytest.mark.parametrize(
        ("text", "reason"),
        [
            ("a\x00b", "NUL"),
            ("x = '''never ends\n", "string is never closed"),
            ("x = 'never ends\n", "string is never closed"),
            ("a {\n b = 1\n", "block is never closed"),
            ("a(1,\n 2\n", "parenthesis is never closed"),
            ("a = 1\n}\n", "closing brace"),
        ],
    )
    def test_a_damaged_script_is_refused_with_the_reason(self, text: str, reason: str) -> None:
        with pytest.raises(ValueError, match=reason):
            GradleScript(text).statements()

    def test_blocks_nested_past_the_limit_are_refused(self) -> None:
        text = "a {\n" * (GradleScript.MAX_DEPTH + 2) + "}\n" * (GradleScript.MAX_DEPTH + 2)
        with pytest.raises(ValueError, match="nested deeper"):
            GradleScript(text).statements()

    def test_more_statements_than_the_limit_are_refused(self) -> None:
        with pytest.raises(ValueError, match="statements"):
            GradleScript("a\n" * (GradleScript.MAX_STATEMENTS + 1)).statements()

    def test_a_semicolon_ends_a_statement_and_a_paren_holds_a_newline(self) -> None:
        statements = GradleScript("a = 1; b = 2\nc(1,\n 2)\n").statements()
        assert [s.text for s in statements] == ["a = 1", "b = 2", "c(1,\n 2)"]
        assert [s.line for s in statements] == [1, 1, 2]


class TestValuesAndCatalog:
    def test_properties_skip_comments_and_blank_lines_and_take_colon_or_equals(self) -> None:
        text = "# note\n! other\n\nversion = 1.2\nname: x\nbare\n= no key\n"
        assert GradleValues.properties(text) == {"version": "1.2", "name": "x"}

    def test_a_template_with_an_unknown_name_is_marked_incomplete(self) -> None:
        assert GradleValues.interpolate("v${known}-$other", {"known": "1"}) == ("v1-$other", False)
        assert GradleValues.interpolate("${project.known}", {"known": "2"}) == ("2", True)

    def test_a_catalog_reads_every_spelling_of_a_library_and_plugin(self) -> None:
        catalog = GradleCatalog.load(
            """
[versions]
strict = { strictly = "1.0" }
plain = "2.0"
empty = { other = "x" }
[libraries]
short = "g:a:3"
unversioned = "g:b"
nocolon = "justone"
viamodule = { module = "g:m", version = { ref = "plain" } }
viaparts = { group = "g", name = "p", version = { strictly = "4" } }
refmissing = { module = "g:r", version = { ref = "nope" } }
broken = { name = "only" }
notatable = 5
[bundles]
set = ["short", "viamodule", 1]
[plugins]
text = "p.id:5"
table = { id = "q.id", version = { ref = "plain" } }
junk = 3
"""
        )
        assert catalog is not None
        assert catalog.versions == {"strict": "1.0", "plain": "2.0", "empty": ""}
        assert catalog.libraries["short"] == ("g:a", "3")
        assert catalog.libraries["unversioned"] == ("g:b", "")
        assert "nocolon" not in catalog.libraries
        assert catalog.libraries["viamodule"] == ("g:m", "2.0")
        assert catalog.libraries["viaparts"] == ("g:p", "4")
        assert catalog.libraries["refmissing"] == ("g:r", "")
        assert "broken" not in catalog.libraries
        assert "notatable" not in catalog.libraries
        assert catalog.bundles["set"] == ["short", "viamodule"]
        assert catalog.plugins["text"] == ("p.id", "5")
        assert catalog.plugins["table"] == ("q.id", "2.0")
        assert "junk" not in catalog.plugins

    def test_a_catalog_that_is_not_toml_is_none(self) -> None:
        assert GradleCatalog.load("[versions\n") is None


class TestRepositories:
    def test_a_maven_call_with_a_url_argument_is_a_named_source(self) -> None:
        statements = GradleScript(
            'repositories {\n  maven("https://repo.example.invalid/m")\n  maven(url = uri("https://r2.example.invalid"))\n}\n'
        ).statements()
        reader = GradleReader("build.gradle.kts", None, {}, kotlin=True)
        reader.read(statements)
        assert reader.build.sources == [
            "repository maven: https://repo.example.invalid/m",
            "repository maven: https://r2.example.invalid",
        ]
