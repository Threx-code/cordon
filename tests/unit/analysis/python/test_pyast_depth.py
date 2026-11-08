"""Python analysis of a long `+` chain: obfuscated files write thousands of terms."""

from __future__ import annotations

import ast

from cordon_scanner.analysis.python.pyast import PythonAnalyzer, PythonSource
from cordon_scanner.analysis.python.pyfacts import PythonFacts
from cordon_scanner.foundation.capabilities import Capability
from support import Support

#: Long enough to pass the default recursion limit (1,000) the old fold hit, short enough to parse.
TERMS = 2_500


class TestLongConcatenation:
    def test_a_long_chain_folds_to_its_string(self) -> None:
        source = " + ".join(["'ab'"] * TERMS)
        node = ast.parse(source, mode="eval").body
        assert PythonFacts.constant(node) == "ab" * TERMS

    def test_a_chain_with_a_computed_term_is_not_folded(self) -> None:
        node = ast.parse("'a' + name + 'b'", mode="eval").body
        assert PythonFacts.constant(node) is None

    def test_a_file_holding_one_is_still_analysed(self) -> None:
        source = (
            "import time\nx = "
            + " + ".join(["'ab'"] * TERMS)
            + "\nwhile True:\n    time.sleep(60)\n"
        )
        assert PythonSource.loop_delay_lines(source) is not None


class TestLongCallChain:
    """A builder chain thousands of links long -- `q.where(a).where(b)...` -- resolved a name one Python
    frame per link and stopped the capability detector (PySegmentKit 0.2.1, a benign PyPI package,
    failed closed for it). Resolved without recursion, the file is read whole: a payload after the chain
    is still found, and the chain itself names nothing."""

    #: Past the old resolver's recursion limit, inside what Python 3.11's own parser accepts (1,500 is not).
    LINKS = 1_200
    CHAIN = "q = builder" + ".where(1)" * LINKS + "\n"

    def test_a_file_holding_one_is_still_analysed(self) -> None:
        payload = Support.assemble(
            "import base64\n", "ex", "ec(base64.b64", "decode('cHJpbnQoMSk='))\n"
        )
        found = {hit.capability for hit in PythonAnalyzer.analyse(self.CHAIN + payload)}
        assert Capability.EXECUTE in found

    @staticmethod
    def _resolved(source: str) -> str | None:
        """The name the analyser resolves the file's last expression to, its tables built."""
        tree = ast.parse(source)
        analyzer = PythonAnalyzer()
        analyzer._collect_names(tree)
        last = tree.body[-1]
        assert isinstance(last, ast.Expr)
        return analyzer._dotted(last.value)

    def test_a_deep_chain_of_attributes_resolves_to_its_dotted_name(self) -> None:
        names = ".".join(f"n{i}" for i in range(self.LINKS))
        assert self._resolved(f"import os\nos.{names}\n") == f"os.{names}"

    def test_an_import_at_the_end_of_a_long_chain_resolves(self) -> None:
        chain = "q" + ".where(1)" * self.LINKS
        source = Support.assemble(f"x = {chain}\n", "__imp", "ort__('base64').b64decode\n")
        assert self._resolved(source) == "base64.b64decode"

    def test_builtins_is_how_a_name_is_reached_not_part_of_it(self) -> None:
        assert (
            self._resolved(Support.assemble("import builtins\nbuiltins.ex", "ec\n")) == "ex" + "ec"
        )
