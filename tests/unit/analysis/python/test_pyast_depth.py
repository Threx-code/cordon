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

    CHAIN = "q = builder" + ".where(1)" * TERMS + "\n"

    def test_a_file_holding_one_is_still_analysed(self) -> None:
        payload = Support.assemble(
            "import base64\n", "ex", "ec(base64.b64", "decode('cHJpbnQoMSk='))\n"
        )
        found = {hit.capability for hit in PythonAnalyzer.analyse(self.CHAIN + payload)}
        assert Capability.EXECUTE in found

    def test_a_deep_chain_of_attributes_resolves_to_its_dotted_name(self) -> None:
        names = ".".join(f"n{i}" for i in range(TERMS))
        source = Support.assemble("import os\nos.", f"{names}()\n")
        assert PythonAnalyzer.analyse(source) is not None
