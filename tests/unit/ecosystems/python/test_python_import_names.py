"""PyPI distributions' import names (`ecosystems/packages/python/import_names`): one read-only table,
and both its readers -- reachability and the advisory-text reader -- take every alias from it."""

from __future__ import annotations

import pytest

from cordon_scanner.detect.supply.reachability import ImportReachability
from cordon_scanner.ecosystems.packages.python.import_names import PythonImportNames
from cordon_scanner.intel.advisories.advisory_text import AdvisoryTextSymbols


class TestTheImportNames:
    def test_the_table_is_read_only(self) -> None:
        with pytest.raises(TypeError):
            PythonImportNames.ALIASES["new"] = ("x",)  # type: ignore[index]

    def test_both_readers_use_every_alias(self) -> None:
        for distribution, aliases in PythonImportNames.ALIASES.items():
            assert set(aliases) <= ImportReachability._import_candidates(distribution)
            canonical, heads = AdvisoryTextSymbols.import_names("pypi", distribution)
            assert canonical == aliases[0]
            assert set(aliases) <= set(heads)

    def test_a_distribution_imported_under_its_own_name_has_none(self) -> None:
        assert PythonImportNames.aliases("requests") == ()
