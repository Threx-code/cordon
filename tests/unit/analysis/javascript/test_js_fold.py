"""JavaScript names split into string fragments, joined back (`detect/js_fold.py`)."""

from __future__ import annotations

from cordon_scanner.analysis.javascript.js_fold import JsFold


class TestFolding:
    def test_a_split_name_joins(self) -> None:
        text = 'require(\'chi\'+\'ld_pro\'+\'cess\')["sp"+"awn"]("rund"+"ll32", [p]);'
        assert JsFold.fold(text) == 'require(\'child_process\')["spawn"]("rundll32", [p]);'

    def test_lines_stay_where_they_were(self) -> None:
        text = "a = 'ev' +\n  'al';\nb = 1;\n"
        folded = JsFold.fold(text)
        assert folded.count("\n") == text.count("\n")
        assert folded.splitlines()[2] == "b = 1;"

    def test_ordinary_concatenation_is_left_alone(self) -> None:
        for text in (
            "const url = 'https://api.example.com' + '/v1/items';",
            "msg = 'Something went wrong' + ' please retry';",
            "const key = 'configuration' + 'directory';",
        ):
            assert JsFold.fold(text) == text
