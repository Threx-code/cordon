"""Every hash spelling Nix accepts is one digest, not a malformed one (review 98)."""

from __future__ import annotations

import pytest

from cordon_scanner.ecosystems.base import Coordinate
from cordon_scanner.ecosystems.nix import Fetchers

NIX32_SHA256 = "0" * 52
BASE64_SHA256 = "A" * 43 + "="


class TestNixHashSpellings:
    @pytest.mark.parametrize(
        ("written", "recorded"),
        [
            (f"sha256-{BASE64_SHA256}", f"sha256-{BASE64_SHA256}"),
            (f"sha256:{NIX32_SHA256}", f"sha256:{NIX32_SHA256}"),
            (NIX32_SHA256, f"sha256:{NIX32_SHA256}"),
            ("a" * 64, "sha256:" + "a" * 64),
            (BASE64_SHA256, f"sha256-{BASE64_SHA256}"),
            ("1" * 103, "sha512:" + "1" * 103),
        ],
    )
    def test_each_spelling_is_a_well_formed_digest(self, written, recorded):
        typed = Fetchers.sri(written)
        assert typed == recorded
        assert not Coordinate.integrity(typed).startswith(Coordinate.MALFORMED)

    def test_a_value_that_is_no_digest_is_still_malformed(self):
        assert Coordinate.integrity(Fetchers.sri("not a hash at all")).startswith(
            Coordinate.MALFORMED
        )
