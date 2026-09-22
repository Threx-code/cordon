"""License string normalisation and classification.

Real declared license strings, not invented ones: the aliases table is built
from spellings that actually appear in `package.json`, npm's legacy
`licenses` array, and PyPI classifiers.
"""

from __future__ import annotations

import pytest

from cordon_scanner.intel.licenses import LicenseCategory, classify, normalize


class TestNormalize:
    def test_none_in_none_out(self) -> None:
        assert normalize(None) is None

    def test_empty_string_is_none(self) -> None:
        assert normalize("") is None
        assert normalize("   ") is None

    def test_an_exact_spdx_id_passes_through(self) -> None:
        assert normalize("MIT") == "MIT"
        assert normalize("Apache-2.0") == "Apache-2.0"

    def test_case_insensitive_spdx_match(self) -> None:
        assert normalize("mit") == "MIT"
        assert normalize("apache-2.0") == "Apache-2.0"

    @pytest.mark.parametrize(
        ("spelling", "expected"),
        [
            ("MIT License", "MIT"),
            ("The MIT License", "MIT"),
            ("Apache 2.0", "Apache-2.0"),
            ("Apache License 2.0", "Apache-2.0"),
            ("Apache Software License", "Apache-2.0"),
            ("New BSD License", "BSD-3-Clause"),
            ("GPLv2", "GPL-2.0-only"),
            ("GPL v3", "GPL-3.0-only"),
            ("GNU General Public License v3.0", "GPL-3.0-only"),
            ("LGPLv2.1", "LGPL-2.1-only"),
            ("AGPLv3", "AGPL-3.0-only"),
            ("Mozilla Public License 2.0", "MPL-2.0"),
            ("Server Side Public License", "SSPL-1.0"),
            ("Public Domain", "Unlicense"),
        ],
    )
    def test_common_non_spdx_spellings(self, spelling: str, expected: str) -> None:
        assert normalize(spelling) == expected

    def test_an_unrecognised_string_is_returned_trimmed_not_dropped(self) -> None:
        assert normalize("  Some Custom EULA  ") == "Some Custom EULA"

    def test_normalize_does_not_evaluate_an_expression(self) -> None:
        # `normalize` produces a single identifier; a compound expression has no
        # single identifier, so it is returned unchanged. Evaluating the
        # expression is `classify`'s job, not this one's.
        assert normalize("(MIT OR Apache-2.0)") == "(MIT OR Apache-2.0)"


class TestClassify:
    @pytest.mark.parametrize(
        "license_str",
        ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "0BSD", "Unlicense", "CC0-1.0"],
    )
    def test_permissive_licenses(self, license_str: str) -> None:
        assert classify(license_str) is LicenseCategory.PERMISSIVE

    @pytest.mark.parametrize("license_str", ["LGPL-2.1-only", "MPL-2.0", "EPL-2.0"])
    def test_weak_copyleft_licenses(self, license_str: str) -> None:
        assert classify(license_str) is LicenseCategory.WEAK_COPYLEFT

    @pytest.mark.parametrize("license_str", ["GPL-2.0-only", "GPL-3.0-only", "GPL-3.0-or-later"])
    def test_strong_copyleft_licenses(self, license_str: str) -> None:
        assert classify(license_str) is LicenseCategory.COPYLEFT

    @pytest.mark.parametrize(
        "license_str", ["AGPL-3.0-only", "AGPL-3.0-or-later", "SSPL-1.0", "OSL-3.0", "EUPL-1.2"]
    )
    def test_network_copyleft_is_its_own_category(self, license_str: str) -> None:
        """A hosted service distributes nothing, so ordinary copyleft does not
        reach it; these licences are written to. The distinction changes who is
        obligated, so it is a different finding."""
        assert classify(license_str) is LicenseCategory.NETWORK_COPYLEFT

    def test_common_spellings_classify_the_same_as_their_spdx_id(self) -> None:
        assert classify("GPLv3") is LicenseCategory.COPYLEFT
        assert classify("MIT License") is LicenseCategory.PERMISSIVE
        assert classify("AGPLv3") is LicenseCategory.NETWORK_COPYLEFT

    def test_none_is_unknown(self) -> None:
        assert classify(None) is LicenseCategory.UNKNOWN

    def test_an_unrecognised_license_is_unknown_not_an_error(self) -> None:
        assert classify("Some Custom EULA") is LicenseCategory.UNKNOWN

    def test_never_raises_on_adversarial_input(self) -> None:
        payloads = ["", " " * 500, "\x00\x01", "a" * 5000, "(((((", "MIT" * 1000]
        for payload in payloads:
            classify(payload)
            normalize(payload)


class TestCompoundExpressions:
    """`OR` is the licensee's choice, `AND` binds every obligation at once, and
    a `WITH` exception only loosens. Treating every expression as UNKNOWN was
    both a miss and a source of noise: a dependency offered as `(MIT OR
    GPL-2.0)` is one the consumer may take under MIT, and reporting it as
    copyleft is a false positive."""

    def test_or_takes_the_least_restrictive_operand(self) -> None:
        assert classify("(MIT OR GPL-2.0-only)") is LicenseCategory.PERMISSIVE
        assert classify("MIT OR AGPL-3.0-only") is LicenseCategory.PERMISSIVE

    def test_and_takes_the_most_restrictive_operand(self) -> None:
        assert classify("GPL-2.0-only AND MIT") is LicenseCategory.COPYLEFT
        assert classify("(AGPL-3.0-only AND MIT)") is LicenseCategory.NETWORK_COPYLEFT

    def test_with_strips_to_the_base_licence(self) -> None:
        assert classify("GPL-2.0-or-later WITH Classpath-exception-2.0") is LicenseCategory.COPYLEFT

    def test_a_known_permissive_option_beats_an_unknown_alternative(self) -> None:
        assert classify("(MIT OR Some-Custom-9.9)") is LicenseCategory.PERMISSIVE

    def test_an_all_unknown_expression_stays_unknown(self) -> None:
        assert classify("(WeirdA AND WeirdB)") is LicenseCategory.UNKNOWN

    def test_the_or_later_suffix_is_not_the_or_operator(self) -> None:
        """`GPL-3.0-or-later` is one identifier, not `GPL-3.0` OR `later`."""
        assert classify("GPL-3.0-or-later") is LicenseCategory.COPYLEFT

    def test_nested_groups(self) -> None:
        assert classify("(MIT OR (GPL-2.0-only AND ISC))") is LicenseCategory.PERMISSIVE
        assert classify("(AGPL-3.0-only OR (GPL-2.0-only AND MIT))") is LicenseCategory.COPYLEFT
