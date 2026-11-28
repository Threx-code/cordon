"""Homebrew's Ruby, as real formulae write it.

Found reading formulae out of real bottles: curl's `def install` holds `args << if OS.mac?` ...
`end` -- an `if` used as a value, which opens a block -- and the reader refused the formula as one
whose blocks do not close. git's `return unless OS.mac?` is a modifier, which opens none. And a
cask was recorded like a formula, though one name can be both (docker).
"""

from __future__ import annotations

import pytest

from cordon_scanner.ecosystems.packages.homebrew import Brewfile, Formula, Ruby
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent


class TestBlocks:
    @pytest.mark.parametrize(
        ("line", "opens"),
        [
            ("args << if OS.mac?", True),
            ("x = if a", True),
            ("value ||= case kind", True),
            ("foo(a, if b", True),
            ("if OS.mac?", True),
            ("return unless OS.mac?", False),  # git's: a modifier
            ('system "make" if build.head?', False),
            ("x = y if z", False),
            ("if a then b end", False),
            ("def name = value", False),
            ('cd "src" do', True),
        ],
    )
    def test_what_opens_a_block(self, line: str, opens: bool) -> None:
        assert Ruby.opens_block(line) is opens

    def test_curls_formula_reads_with_its_stable_source(self) -> None:
        text = (
            "class Curl < Formula\n"
            '  url "https://curl.se/download/curl-8.0.0.tar.bz2"\n'
            '  head "https://github.com/curl/curl.git", branch: "master"\n'
            "  def install\n"
            "    args << if OS.mac?\n"
            '      "--with-gssapi"\n'
            "    else\n"
            '      "--without-gssapi"\n'
            "    end\n"
            "    return unless OS.mac?\n"
            "  end\n"
            "end\n"
        )
        manifest = Formula.parse(
            FileContent.from_bytes("Formula/c/curl.rb", text.encode()), "homebrew"
        )
        assert manifest.parse_error is None
        assert "source https://curl.se/download/curl-8.0.0.tar.bz2" in manifest.sources
        assert any(s.startswith("head https://github.com/curl/curl.git") for s in manifest.sources)


class TestCasks:
    def test_a_cask_is_marked_as_one(self) -> None:
        manifest = Brewfile.parse(
            FileContent.from_bytes("Brewfile", b'brew "docker"\ncask "docker"\n'), "homebrew"
        )
        assert sorted(d.platform for d in manifest.dependencies) == [(), ("cask",)]


class TestOtherPackageManagers:
    """`brew bundle` installs through other package managers too: each Bundle extension's name is the Brewfile
    keyword (Homebrew's Library/Homebrew/bundle/extensions/). Their packages belong to their own ecosystem."""

    TEXT = (
        'brew "jq"\n'
        'vscode "Ms-Python.Python"\n'
        'cargo "ripgrep"\n'
        'go "golang.org/x/tools/gopls"\n'
        'npm "prettier"\n'
        'uv "ruff"\n'
        'krew "ctx"\n'
        'flatpak "org.mozilla.firefox"\n'
        'winget "Git.Git"\n'
    )

    def manifest(self):
        return Brewfile.parse(FileContent.from_bytes("Brewfile", self.TEXT.encode()), "homebrew")

    def test_each_is_recorded_under_its_own_ecosystem(self) -> None:
        found = {(d.name, d.ecosystem) for d in self.manifest().dependencies}
        assert {
            ("jq", None),
            ("ms-python.python", "vscode"),
            ("ripgrep", "cargo"),
            ("golang.org/x/tools/gopls", "gomod"),
            ("prettier", "npm"),
            ("ruff", "pypi"),
        } <= found

    def test_ones_no_ecosystem_holds_are_named_not_dropped(self) -> None:
        manifest = self.manifest()
        names = {d.name for d in manifest.dependencies}
        assert not {"ctx", "org.mozilla.firefox", "git.git", "Git.Git"} & names
        sources = " ".join(manifest.sources)
        assert "krew" in sources and "flatpak" in sources and "winget" in sources

    def test_every_declared_keyword_is_one_the_reader_reads(self) -> None:
        """An adapter declaring a Bundle keyword the Brewfile reader does not match would be dropped quietly."""
        for keyword in (*Brewfile.other_ecosystems(), *Brewfile.UNCHECKED):
            parsed = Brewfile.parse(
                FileContent.from_bytes("Brewfile", f'{keyword} "a.b"\n'.encode()), "homebrew"
            )
            assert parsed.dependencies or parsed.sources, keyword
        assert set(Brewfile.other_ecosystems()) == {"vscode", "cargo", "go", "npm", "uv"}

    def test_the_registry_fills_the_table_from_every_adapter_that_declares_one(self) -> None:
        declared = {
            getattr(e, "bundle_keyword", None): e.id
            for e in EcosystemRegistry.all_ecosystems()
            if getattr(e, "bundle_keyword", None)
        }
        assert declared == Brewfile.other_ecosystems()
