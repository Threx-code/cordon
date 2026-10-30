"""The licence port (`intel.base.LicenseClassification`, `LicenseCategory`): the category is one enum
wherever it is imported from, and the port's names answer what the classifier always did."""

from __future__ import annotations

from cordon_scanner.intel import base, registry
from cordon_scanner.intel.store import licenses
from cordon_scanner.intel.store.licenses import LicenseClassifier


class LicenseKit:
    EXPRESSIONS = (
        "MIT",
        "MIT OR Apache-2.0",
        "(MIT OR GPL-3.0) AND BSD-2-Clause",
        "GPL-2.0-only WITH Classpath-exception-2.0",
        "((AGPL-3.0 OR MPL-2.0) AND (LGPL-2.1 OR ISC))",
        "Apache-2.0 AND (MIT OR (GPL-2.0 AND LGPL-3.0))",
        "",
        "(unbalanced OR MIT",
    )


class TestTheLicencePort:
    def test_the_category_is_one_enum(self) -> None:
        assert licenses.LicenseCategory is base.LicenseCategory
        assert registry.LICENSE_UNKNOWN is base.LicenseCategory.UNKNOWN

    def test_split_top_level_is_the_classifiers_own(self) -> None:
        for expression in LicenseKit.EXPRESSIONS:
            for operator in (" OR ", " AND ", " WITH "):
                assert LicenseClassifier.split_top_level(expression, operator) == (
                    LicenseClassifier._split_top_level(expression, operator)
                )

    def test_the_role_classifies_and_normalizes_as_before(self) -> None:
        role = registry.LicenseClassifier
        for expression in LicenseKit.EXPRESSIONS:
            assert role.classify(expression) is LicenseClassifier.classify(expression)
            assert role.normalize(expression) == LicenseClassifier.normalize(expression)
