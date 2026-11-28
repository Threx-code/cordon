"""The dune readers on the shapes a real project writes less often: comments of every kind,
constraint filters, a workspace's contexts, and a lock package that cannot be read."""

from __future__ import annotations

import pytest

from cordon_scanner.ecosystems.packages.ocaml.dune import (
    DuneLock,
    DuneProject,
    DuneWorkspace,
    Sexp,
)
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits
from cordon_scanner.foundation.models import Scope


class _Kit:
    @staticmethod
    def fc(path: str, text: str) -> FileContent:
        return FileContent.from_bytes(path, text.encode("utf-8"), Limits())


fc = _Kit.fc


class TestSexp:
    def test_comments_of_every_kind_are_dropped(self) -> None:
        text = '(a ; line\n #| block\n (b) |# #;(skipped c) d "e\\"f")\n'
        assert Sexp.parse(text) == [["a", "d", 'e"f']]

    @pytest.mark.parametrize(
        ("text", "reason"),
        [
            ("(a #| never", "unterminated block comment"),
            ("(a))", "nothing open"),
            ('(a "open', "unterminated string"),
            ("(a", "does not close"),
        ],
    )
    def test_text_that_is_not_balanced_is_refused(self, text: str, reason: str) -> None:
        with pytest.raises(ValueError, match=reason):
            Sexp.parse(text)

    def test_nesting_past_the_limit_is_refused(self) -> None:
        with pytest.raises(ValueError, match="too deeply"):
            Sexp.parse("(" * (Sexp.MAX_DEPTH + 2))


class TestConstraints:
    def test_an_and_or_joins_constraints_and_keeps_the_flag_scope(self) -> None:
        form = Sexp.parse("(and (>= 1.0) (< 2.0) :with-test)")[0]
        assert DuneProject.constraint(form) == ([">= 1.0 & < 2.0"], Scope.TEST, [])
        either = Sexp.parse("(or (= 1) (= 2))")[0]
        assert DuneProject.constraint(either) == (["= 1 | = 2"], None, [])

    def test_a_not_equal_is_spelled_the_usual_way_and_a_variable_filter_is_a_condition(
        self,
    ) -> None:
        assert DuneProject.constraint(["<>", "3"]) == (["!= 3"], None, [])
        assert DuneProject.constraint(["=", ":os", "linux"]) == ([], None, ["os = linux"])

    @pytest.mark.parametrize("form", [[], 7, ["weird", "x"], ["=", "a", "b", "c"]])
    def test_a_form_that_is_no_constraint_says_nothing(self, form: object) -> None:
        assert DuneProject.constraint(form) == ([], None, [])


class TestProjectAndWorkspace:
    def test_a_project_declares_its_dependencies_with_scope_and_notes(self) -> None:
        text = """(lang dune 3.0)
(generate_opam_files true)
(package (name demo)
 (depends dune (alcotest :with-test) (ocaml (>= 4.14)) (lwt (and (>= 5) (= :os linux))) 7)
 (depopts (fmt (< 1))))
(pin (url "git+https://h.example/x.git") (package (name pinned)))
"""
        manifest = DuneProject.parse(fc("dune-project", text), "opam")
        by_name = {d.name: d for d in manifest.dependencies}
        assert by_name["dune"].note is not None and "build" in by_name["dune"].note
        assert by_name["alcotest"].scope == Scope.TEST
        assert by_name["alcotest"].note is not None and "with-test" in by_name["alcotest"].note
        assert by_name["ocaml"].scope == Scope.PLATFORM
        assert by_name["lwt"].platform == ("os = linux",)
        assert by_name["fmt"].scope == Scope.OPTIONAL
        assert manifest.name == "demo"
        assert manifest.sources == ("dune generates demo.opam (generate_opam_files)",)
        assert "pinned" in manifest.source_patterns

    def test_a_project_that_cannot_be_read_or_has_no_lang_is_an_error(self) -> None:
        assert "not a readable dune-project" in str(
            DuneProject.parse(fc("dune-project", "(lang"), "opam").parse_error
        )
        assert "without its" in str(
            DuneProject.parse(fc("dune-project", "(name x)"), "opam").parse_error
        )

    def test_a_workspace_lists_its_contexts_and_repositories(self) -> None:
        text = """(lang dune 3.0)
(context (opam (switch 5.1.0)))
(context (opam))
(context default)
(repository (name mine) (url "git+https://h.example/r"))
(repository (url "https://h.example/anon"))
"""
        manifest = DuneWorkspace.parse(fc("dune-workspace", text), "opam")
        assert manifest.sources == (
            "context on opam switch 5.1.0",
            "context on an opam switch",
            "context default",
            "repository mine git+https://h.example/r",
            "repository https://h.example/anon",
        )
        assert DuneWorkspace.parse(fc("dune-workspace", "(a"), "opam").parse_error


class TestLock:
    def test_repositories_used_are_listed_and_a_broken_file_is_an_error(self) -> None:
        text = (
            '(repositories (used ((source "https://h.example/a"))'
            ' ((source "https://h.example/b")) (x)))'
        )
        manifest = DuneLock.repositories(fc("dune.lock/lock.dune", text), "opam")
        assert manifest.sources == (
            "repository https://h.example/a",
            "repository https://h.example/b",
        )
        assert DuneLock.repositories(fc("dune.lock/lock.dune", "(x"), "opam").parse_error

    def test_a_package_names_its_dependencies_and_skips_platform_filters(self) -> None:
        text = """(version 1.2.3)
(depends a (all_platforms (b c)) (os linux) :flag)
(source (fetch (url https://h.example/a.tgz) (checksum sha256=abc)))
"""
        graph = DuneLock.package(fc("dune.lock/demo.1.2.3.pkg", text), "opam")
        assert graph.parse_error is None
        (entry,) = graph.entries
        assert entry.name == "demo"
        assert entry.version == "1.2.3"
        assert set(entry.dependencies) == {"a", "b", "c"}

    def test_a_package_that_is_unreadable_or_has_no_version_is_an_error(self) -> None:
        assert "not a readable" in str(
            DuneLock.package(fc("dune.lock/x.pkg", "(version"), "opam").parse_error
        )
        assert "without its version" in str(
            DuneLock.package(fc("dune.lock/x.pkg", "(depends a)"), "opam").parse_error
        )
