"""Python analysis of a long `+` chain: obfuscated files write thousands of terms."""

from __future__ import annotations

import ast

from cordon_scanner.detect.pyast import PythonAnalyzer, PythonSource

#: Long enough to pass the default recursion limit (1,000) the old fold hit, short enough to parse.
TERMS = 2_500


class TestLongConcatenation:
    def test_a_long_chain_folds_to_its_string(self) -> None:
        source = " + ".join(["'ab'"] * TERMS)
        node = ast.parse(source, mode="eval").body
        assert PythonAnalyzer.constant(node) == "ab" * TERMS

    def test_a_chain_with_a_computed_term_is_not_folded(self) -> None:
        node = ast.parse("'a' + name + 'b'", mode="eval").body
        assert PythonAnalyzer.constant(node) is None

    def test_a_file_holding_one_is_still_analysed(self) -> None:
        source = (
            "import time\nx = "
            + " + ".join(["'ab'"] * TERMS)
            + "\nwhile True:\n    time.sleep(60)\n"
        )
        assert PythonSource.loop_delay_lines(source) is not None
