"""Gemfile blocks, gemspecs and Gemfile.lock lines on the shapes written less often (`ecosystems/packages/rubygems.py`)."""

from __future__ import annotations

from typing import Any

from cordon_scanner.ecosystems.packages.rubygems import BundlerLock, RubySource
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits
from cordon_scanner.foundation.models import Scope


class _Kit:
    @staticmethod
    def fc(path: str, text: str) -> FileContent:
        return FileContent.from_bytes(path, text.encode("utf-8"), Limits())

    @staticmethod
    def adapter() -> Any:
        return EcosystemRegistry.BY_ID["rubygems"]

    @staticmethod
    def gemfile(text: str) -> Any:
        return _Kit.adapter().parse_manifest(_Kit.fc("Gemfile", text))


class TestSymbols:
    def test_a_value_given_as_a_quoted_name_a_list_of_symbols_or_one_symbol_is_read(self) -> None:
        assert RubySource.symbols('gem "x", group: "test"', "group") == ["test"]
        assert RubySource.symbols('gem "x", group: [:a, :b]', "group") == ["a", "b"]
        assert RubySource.symbols('gem "x", group: :a', "group") == ["a"]
        assert RubySource.symbols('gem "x", group: %i[a b]', "group") == ["a", "b"]
        assert RubySource.symbols('gem "x"', "group") == []


class TestGemfileBlocks:
    def test_an_end_with_no_block_open_is_an_error_naming_the_line(self) -> None:
        manifest = _Kit.gemfile('source "https://rubygems.org"\nend\n')
        assert "line 2: `end` with no block open" in manifest.parse_error

    def test_git_github_and_path_blocks_give_their_gems_a_source(self) -> None:
        text = (
            'source "https://rubygems.org"\n'
            'git "https://git.example.invalid/o/x.git" do\n  gem "x"\nend\n'
            'github "o/y" do\n  gem "y"\nend\n'
            'github "https://github.com/o/z.git" do\n  gem "z"\nend\n'
            'path "vendor/q" do\n  gem "q"\nend\n'
        )
        by_name = {d.name: d for d in _Kit.gemfile(text).dependencies}
        assert by_name["x"].spec == "git+https://git.example.invalid/o/x.git"
        assert by_name["y"].spec == "git+https://github.com/o/y.git"
        assert by_name["z"].spec == "git+https://github.com/o/z.git"
        assert by_name["q"].spec == "path:vendor/q"

    def test_a_gem_in_the_test_group_is_a_test_dependency_and_in_development_a_dev_one(
        self,
    ) -> None:
        text = (
            'source "https://rubygems.org"\n'
            'group :test do\n  gem "rspec"\nend\n'
            'group :development do\n  gem "pry"\nend\n'
            'gem "minitest", group: :test\n'
        )
        scopes = {d.name: d.scope for d in _Kit.gemfile(text).dependencies}
        assert scopes == {"rspec": Scope.TEST, "pry": Scope.DEV, "minitest": Scope.TEST}

    def test_an_escaped_quote_inside_a_string_does_not_end_it(self) -> None:
        text = 'source "https://rubygems.org"\ngem "a", require: "x\\"y"\n'
        assert [d.name for d in _Kit.gemfile(text).dependencies] == ["a"]


class TestGemspecs:
    def test_a_gemspec_that_cannot_be_read_is_an_error_where_it_is_parsed_and_skipped_beside_a_gemfile(
        self,
    ) -> None:
        broken = _Kit.fc(
            "lib/x.gemspec", "Gem::Specification.new do |s|\n  s.name = 'unterminated\n"
        )
        manifest = _Kit.adapter().parse_manifest(broken)
        assert manifest.parse_error.startswith("not a readable gemspec")
        gemfile = _Kit.fc("Gemfile", 'source "https://rubygems.org"\ngemspec path: "lib"\n')
        files = {"Gemfile": gemfile, "lib/x.gemspec": broken}
        beside = _Kit.adapter().parse_in_tree(gemfile, files)
        assert not beside.parse_error

    def test_the_ruby_a_gemspec_requires_is_a_platform_dependency_of_the_gemfile_that_names_it(
        self,
    ) -> None:
        spec = (
            "Gem::Specification.new do |s|\n  s.name = 'x'\n  s.required_ruby_version = '>= 3.1'\n"
            "  s.add_dependency 'rack', '~> 2'\nend\n"
        )
        gemfile = _Kit.fc("Gemfile", 'source "https://rubygems.org"\ngemspec\n')
        files = {"Gemfile": gemfile, "x.gemspec": _Kit.fc("x.gemspec", spec)}
        manifest = _Kit.adapter().parse_in_tree(gemfile, files)
        names = {d.name: d.scope for d in manifest.dependencies}
        assert names.get("ruby") is Scope.PLATFORM
        assert "rack" in names


class TestGemspecScopes:
    def test_a_development_dependency_in_the_test_group_is_a_test_dependency(self) -> None:
        from cordon_scanner.ecosystems.packages.rubygems import Gemspec

        content = _Kit.fc("x.gemspec", "s.add_development_dependency 'rspec'\n")
        [dependency], _, _ = Gemspec.read(content, "test")
        assert dependency.scope is Scope.TEST


class TestBundlerLock:
    def test_a_version_with_no_platform_is_kept_whole(self) -> None:
        assert BundlerLock.split("~> weird") == ("~> weird", None)
        assert BundlerLock.split("1.19.4-x86_64-linux") == ("1.19.4", "x86_64-linux")

    def test_a_projects_own_gemspec_in_a_path_section_is_the_project_not_a_dependency(self) -> None:
        text = (
            "PATH\n  remote: .\n  specs:\n    mine (1.0.0)\n\n"
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.8)\n\n"
            "DEPENDENCIES\n  mine!\n  rack\n\nBUNDLED WITH\n   2.5.0\n"
        )
        files = {
            "Gemfile.lock": _Kit.fc("Gemfile.lock", text),
            "mine.gemspec": _Kit.fc(
                "mine.gemspec", "Gem::Specification.new { |s| s.name = 'mine' }\n"
            ),
        }
        graph = BundlerLock.parse(files["Gemfile.lock"], "rubygems", frozenset({"mine"}))
        names = {e.name for e in graph.entries}
        assert "rack" in names and "mine" not in names

    def test_a_spec_or_dependency_line_that_is_neither_is_counted_as_unreadable(self) -> None:
        text = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.8)\n  !!!\n"
        assert _Kit.adapter().parse_lockfile(_Kit.fc("Gemfile.lock", text)) is not None

    def test_a_checksums_line_that_is_not_a_gem_and_digest_is_counted_not_guessed(self) -> None:
        text = (
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.8)\n\n"
            "CHECKSUMS\n  rack (2.2.8) sha256=" + "a" * 64 + "\n  garbage line here\n"
        )
        graph = BundlerLock.parse(_Kit.fc("Gemfile.lock", text), "rubygems")
        assert [(e.name, e.integrity) for e in graph.entries] == [("rack", "sha256:" + "a" * 64)]
