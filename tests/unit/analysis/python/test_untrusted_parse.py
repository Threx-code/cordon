"""Every parse of scanned Python goes through PythonSyntax.parse, which silences the warnings
`ast.parse` raises about the source. A direct `ast.parse` prints them into the user's output and,
where warnings are errors (PYTHONWARNINGS=error, common in CI), turns a file with an invalid escape
into an unparsed file whose code is never read."""

from __future__ import annotations

import re
import warnings

from cordon_scanner.analysis.python.py_flow_facts import PythonFlowFacts
from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from support import ROOT

#: Files that parse our own source, not a scanned file's.
OWN_SOURCE = {"decide/feature_schema.py", "analysis/python/pysyntax.py"}


class TestUntrustedParse:
    def test_no_scanned_source_is_parsed_past_the_guard(self) -> None:
        src = ROOT / "src" / "cordon_scanner"
        direct = sorted(
            p.relative_to(src).as_posix()
            for p in src.rglob("*.py")
            if p.relative_to(src).as_posix() not in OWN_SOURCE
            and re.search(r"\bast\.parse\(", p.read_text(encoding="utf-8"))
        )
        assert direct == []

    def test_an_invalid_escape_still_parses_where_warnings_are_errors(self) -> None:
        source = 'import os\npattern = "\\s+"\nos.system(pattern)\n'
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            assert PythonSyntax.parse(source) is not None
            assert PythonFlowFacts.of(source) is not None
