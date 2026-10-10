"""Scanned Python is parsed without printing the warnings it raises.

Found scanning real repositories: stable-diffusion's invalid escapes (`"\\h"`) made `ast.parse`
write seven `SyntaxWarning`s to the scanner's stderr, which reads as the scanner failing in a CI
log. The source below raises two such warnings under a bare `ast.parse`.
"""

from __future__ import annotations

import warnings

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config
from cordon_scanner.core.pysyntax import PythonSyntax


class TestScannedPythonRaisesNoWarning:
    SOURCE = 'WINDOWS = "C:\\home\\x41"\nODD = "\\h"\n'

    def test_an_invalid_escape_in_scanned_code_is_not_printed(self, tmp_path) -> None:
        (tmp_path / "paths.py").write_text(self.SOURCE, encoding="utf-8")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            PythonSyntax.parse(self.SOURCE)
            Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        assert [w for w in caught if issubclass(w.category, SyntaxWarning)] == []

    def test_a_syntax_error_is_still_raised(self) -> None:
        import pytest

        with pytest.raises(SyntaxError):
            PythonSyntax.parse("def (:\n")
