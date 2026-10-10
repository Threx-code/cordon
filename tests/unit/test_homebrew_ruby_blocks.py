"""Homebrew's Ruby, as real formulae write it.

Found reading formulae out of real bottles: curl's `def install` holds `args << if OS.mac?` ...
`end` -- an `if` used as a value, which opens a block -- and the reader refused the formula as one
whose blocks do not close. git's `return unless OS.mac?` is a modifier, which opens none. And a
cask was recorded like a formula, though one name can be both (docker).
"""

from __future__ import annotations

import pytest

from cordon_scanner.core.content import FileContent
from cordon_scanner.ecosystems.homebrew import Brewfile, Formula, Ruby


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
