"""A heredoc's body is text, not Ruby: its lines open and close no block."""

from __future__ import annotations

from cordon_scanner.ecosystems.packages.homebrew import Formula, Ruby
from cordon_scanner.foundation.content import FileContent

FORMULA = """class PythonAT313 < Formula
  url "https://www.python.org/ftp/python/3.13.0/Python-3.13.0.tgz"
  sha256 "12445c7b3db3126c41190bfdc1c8239c39c719404e844babbd015a1bc3fafcd4"

  def sitecustomize
    <<~EOS
      import sys
      if sys.version_info[:2] != (3, 13):
          raise SystemExit
      while False:
          pass
    EOS
  end

  def install
    (lib/"x").write <<-'PY'
      if True: begin_here = 1
    PY
    args << "<<EOS is in a string"
    system "make"
  end
end
"""


class TestHeredocs:
    def test_python_in_a_heredoc_leaves_the_formula_balanced(self) -> None:
        assert Ruby.balanced(FORMULA)
        manifest = Formula.parse(
            FileContent.from_bytes("Formula/python@3.13.rb", FORMULA.encode()), "homebrew"
        )
        assert (
            "source https://www.python.org/ftp/python/3.13.0/Python-3.13.0.tgz" in manifest.sources
        )

    def test_markers(self) -> None:
        assert Ruby.heredocs("x.write <<~EOS") == [(True, "EOS")]
        assert Ruby.heredocs("a(<<-'A', <<B)") == [(True, "A"), (False, "B")]
        assert Ruby.heredocs('args << "<<EOS"') == []
        assert Ruby.heredocs("args << DEFAULTS") == []


class TestWordsInStrings:
    def test_a_keyword_inside_a_string_opens_no_block(self) -> None:
        assert not Ruby.opens_block(
            'desc "Smooth out the rough edges (temporarily, until AWS makes it better)"'
        )
        assert not Ruby.opens_block('desc "Things to do"')
        assert Ruby.opens_block('resource "attrs" do')
        assert Ruby.opens_block("args << if OS.mac?")

    def test_do_after_a_regex_literal_holding_quotes_opens_a_block(self) -> None:
        assert Ruby.opens_block("""page.scan(/href=.*?bash[._-]?v?\\d+["' >]/i).each do |match|""")

    def test_the_data_after_end_is_not_code(self) -> None:
        text = 'class Gcl < Formula\n  patch :DATA\nend\n__END__\n-    (unless (eq r "eof)\n+    (unless x)\n'
        assert Ruby.balanced(text)
