"""Homebrew bottles against their GitHub build attestations (`intel/homebrew_provenance`).

Offline: Homebrew's API, GitHub's attestation API and the sigstore verifier are stood in for, so
what is tested is the decision -- which bottles are asked about, and what each answer means. The
cryptography is `attest.SigstoreVerification`'s, tested with the npm and PyPI attestations; it was
checked against homebrew-core's real bottles (wget, jq) when this was written, and rejects a
genuine bundle offered for another bottle's digest or under another repository.
"""

from __future__ import annotations

import urllib.error

import pytest

from cordon_scanner.intel import attest
from cordon_scanner.intel.homebrew_provenance import SOURCE_REPO, HomebrewProvenance

FORMULA = {
    "versions": {"stable": "1.25.0"},
    "bottle": {
        "stable": {
            "files": {
                "arm64_sequoia": {"sha256": "a" * 64},
                "x86_64_linux": {"sha256": "b" * 64},
            }
        }
    },
}


class FakeApis:
    def __init__(
        self, monkeypatch, *, formula=FORMULA, attested=True, verdict=attest.Outcome.VERIFIED
    ):
        self.asked: list[str] = []
        self.verified: list[tuple[str, tuple]] = []

        def get(url: str):
            self.asked.append(url)
            if "formulae.brew.sh" in url:
                if formula is None:
                    raise urllib.error.HTTPError(url, 404, "not found", None, None)
                return formula
            return (
                {"attestations": [{"bundle": {"for": url.rsplit(":", 1)[1]}}]} if attested else {}
            )

        def verify(bundle, *, digest_hex, algorithm, source_repo, offline=False):
            self.verified.append((digest_hex, source_repo))
            return attest.Result(verdict, "stood in")

        monkeypatch.setattr(HomebrewProvenance, "_get", staticmethod(get))
        monkeypatch.setattr(attest.SigstoreVerification, "verify", staticmethod(verify))


class TestHomebrewBottles:
    @pytest.mark.conformance("homebrew", "UNI-17")
    def test_every_bottle_is_verified_against_its_own_digest(self, monkeypatch) -> None:
        apis = FakeApis(monkeypatch)
        result = HomebrewProvenance.check("wget", None)
        assert result.outcome == "verified"
        assert sorted(digest for digest, _ in apis.verified) == ["a" * 64, "b" * 64]
        # Under homebrew-core's identity, not a repository the formula names.
        assert {repo for _, repo in apis.verified} == {SOURCE_REPO}

    @pytest.mark.conformance("homebrew", "UNI-17")
    def test_an_attestation_that_does_not_cover_the_bottle_is_invalid(self, monkeypatch) -> None:
        FakeApis(monkeypatch, verdict=attest.Outcome.INVALID)
        assert HomebrewProvenance.check("wget", None).outcome == "invalid"

    def test_a_bottle_with_no_attestation_is_not_a_pass(self, monkeypatch) -> None:
        FakeApis(monkeypatch, attested=False)
        result = HomebrewProvenance.check("wget", None)
        assert result.outcome == "unverifiable"
        assert "no build attestation" in result.detail

    def test_an_older_version_than_the_api_serves_is_not_checked_against_the_wrong_bottles(
        self, monkeypatch
    ) -> None:
        apis = FakeApis(monkeypatch)
        result = HomebrewProvenance.check("wget", "1.21.0")
        assert result.outcome == "unverifiable"
        assert not apis.verified
        # A revision suffix is the same version.
        assert HomebrewProvenance.check("wget", "1.25.0_2").outcome == "verified"

    def test_a_cask_and_a_third_party_tap_have_nothing_to_verify(self, monkeypatch) -> None:
        FakeApis(monkeypatch, formula=None)
        assert HomebrewProvenance.check("visual-studio-code", None).outcome == "absent"
        assert HomebrewProvenance.check("someone/tap/thing", None).outcome == "absent"

    def test_an_unreachable_api_is_unverifiable(self, monkeypatch) -> None:
        def down(url):
            raise urllib.error.URLError("no route")

        monkeypatch.setattr(HomebrewProvenance, "_get", staticmethod(down))
        assert HomebrewProvenance.check("wget", None).outcome == "unverifiable"
