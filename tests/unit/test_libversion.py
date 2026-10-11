"""libversion's ordering (Repology), as its documentation states it, and the packaging revisions
that are not part of a release."""

from __future__ import annotations

import pytest

from cordon_scanner.intel.versions import LibVersion, Versions


class TestLibVersion:
    @pytest.mark.parametrize(
        ("lower", "higher"),
        [
            ("0.99", "1.0"),
            ("1.0alpha1", "1.0"),
            ("1.0alpha1", "1.0beta1"),
            ("1.0beta1", "1.0rc1"),
            ("1.0rc1", "1.0"),
            ("1.0", "1.0a"),
            ("1.0", "1.0patch1"),
            ("1.0patch1", "1.0.1"),
            ("1.0", "1.0.1"),
            ("9.0", "10.0"),
            ("2.4.9", "2.4.10"),
            ("1.0a", "1.0b"),
            ("1.0beta", "1.0"),
        ],
    )
    def test_order(self, lower: str, higher: str) -> None:
        assert LibVersion.compare(lower, higher) == -1
        assert LibVersion.compare(higher, lower) == 1

    @pytest.mark.parametrize(
        ("a", "b"),
        [("1.0", "1.0.0"), ("1.0alpha1", "1.0a1"), ("1_0", "1.0"), ("1.0-rc1", "1.0rc1")],
    )
    def test_equal(self, a: str, b: str) -> None:
        assert LibVersion.compare(a, b) == 0

    def test_a_packaging_revision_is_not_the_release(self) -> None:
        assert Versions.compare("homebrew", "3.46.0_1", "3.46.0") == 0
        assert Versions.compare("vcpkg", "3.46.0#2", "3.46.0") == 0
        assert Versions.in_range(
            "homebrew", "3.46.0_2", introduced="3.40.0", last_affected="3.46.0"
        )
        assert not Versions.in_range("conan", "10.0", fixed="9.1")
