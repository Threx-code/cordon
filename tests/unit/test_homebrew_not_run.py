"""The parts of a formula `brew install` never runs (review 98, FP-13)."""

from __future__ import annotations

from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config
from cordon_scanner.ecosystems.homebrew import NotRunAtInstall

#: Shaped on homebrew-core's `liquidprompt.rb`: the caveats tell the user what to add to a profile.
CAVEATS = """class Liquidprompt < Formula
  desc "Adaptive prompt for bash and zsh shells"
  url "https://example.invalid/liquidprompt-2.1.2.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"

  def install
    share.install Dir["*"]
  end

  def caveats
    <<~EOS
      Add the following lines to your bash or zsh config (e.g. ~/.bash_profile):
        if [ -f #{HOMEBREW_PREFIX}/share/liquidprompt ]; then
          . #{HOMEBREW_PREFIX}/share/liquidprompt
        fi
    EOS
  end

  service do
    run [opt_bin/"liquidprompt-daemon"]
    keep_alive true
  end

  test do
    system "true"
  end
end
"""

#: The same line written by `install` itself: that is what the rule is for.
WRITTEN = CAVEATS.replace(
    '    share.install Dir["*"]\n',
    '    share.install Dir["*"]\n'
    '    (Pathname.new(Dir.home)/".bash_profile").append_lines ". #{share}/liquidprompt"\n',
)


class HomebrewKit:
    @staticmethod
    def rules(tmp_path: Path, formula: str) -> set[str]:
        (tmp_path / "Formula").mkdir()
        (tmp_path / "Formula" / "liquidprompt.rb").write_text(formula, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return {f.rule_id for f in result.findings}


class TestNotRunAtInstall:
    def test_the_spans_are_caveats_service_and_test(self) -> None:
        lines = CAVEATS.splitlines()
        spans = NotRunAtInstall.spans(CAVEATS)
        opened = {
            lines[first - 1].strip().split()[0] + " " + lines[first - 1].strip().split()[1]
            if lines[first - 1].strip().startswith("def")
            else lines[first - 1].strip().split()[0]
            for first, _ in spans
        }
        assert opened == {"def caveats", "service", "test"}
        install = next(i for i, line in enumerate(lines, 1) if line.strip() == "def install")
        assert not any(first <= install <= last for first, last in spans)

    def test_a_caskroom_caveats_heredoc_is_a_span(self) -> None:
        cask = 'cask "x" do\n  caveats <<~EOS\n    Add x to ~/.zshrc\n  EOS\n  postflight do\n    system "true"\n  end\nend\n'
        assert (2, 4) in NotRunAtInstall.spans(cask)


class TestAFormula:
    def test_whose_caveats_name_a_profile_is_not_persistence(self, tmp_path: Path) -> None:
        assert "MALWARE.INSTALL.PERSIST.001" not in HomebrewKit.rules(tmp_path, CAVEATS)

    def test_whose_install_writes_the_profile_still_is(self, tmp_path: Path) -> None:
        assert "MALWARE.INSTALL.PERSIST.001" in HomebrewKit.rules(tmp_path, WRITTEN)
