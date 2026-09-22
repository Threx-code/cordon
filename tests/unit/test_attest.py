"""The provenance verifier, tested without a live trust root or a real bundle.

The cryptographic verification itself belongs to sigstore, and reaching its
production trust root needs the network -- so the boundary is what is tested
here: that a digest string parses to the right bytes, that a registry document
becomes bundle JSON, that every reason a check cannot run is reported as
`UNVERIFIABLE` and only a cryptographic or identity rejection as `INVALID`, and
that a real, unparseable bundle is refused rather than crashed on. The sigstore
call is substituted where the test is about the outcome mapping rather than the
signature maths.
"""

from __future__ import annotations

import json
from typing import ClassVar

import pytest

from cordon_scanner.intel import attest
from cordon_scanner.intel.attest import Outcome


class TestParseIntegrity:
    def test_npm_style_sha512_subresource_integrity(self) -> None:
        import base64

        raw = bytes(range(64))
        value = "sha512-" + base64.b64encode(raw).decode()
        assert attest.parse_integrity(value) == ("sha512", raw.hex())

    def test_pip_style_prefixed_hex(self) -> None:
        digest = "ab" * 32
        assert attest.parse_integrity(f"sha256:{digest}") == ("sha256", digest)

    def test_a_wrong_length_digest_is_rejected(self) -> None:
        assert attest.parse_integrity("sha256:abcd") is None

    def test_an_unknown_algorithm_is_rejected(self) -> None:
        assert attest.parse_integrity("md5:" + "aa" * 16) is None

    def test_empty_and_shapeless_input_is_none(self) -> None:
        assert attest.parse_integrity(None) is None
        assert attest.parse_integrity("") is None
        assert attest.parse_integrity("no-separator-here") is None


class TestExtractBundles:
    def test_npm_attestations_become_bundle_json(self) -> None:
        payload = {
            "attestations": [
                {"predicateType": "slsaprovenance", "bundle": {"a": 1}},
                {"predicateType": "publish", "bundle": {"b": 2}},
            ]
        }
        bundles = attest.extract_bundles("npm", payload)
        assert [json.loads(b) for b in bundles] == [{"a": 1}, {"b": 2}]

    def test_an_npm_entry_without_a_bundle_is_skipped(self) -> None:
        payload = {"attestations": [{"predicateType": "x"}, {"bundle": {"ok": 1}}]}
        assert [json.loads(b) for b in attest.extract_bundles("npm", payload)] == [{"ok": 1}]

    def test_an_empty_or_shapeless_payload_yields_nothing(self) -> None:
        assert attest.extract_bundles("npm", None) == ()
        assert attest.extract_bundles("npm", {}) == ()
        assert attest.extract_bundles("npm", {"attestations": "not-a-list"}) == ()

    def test_an_unsupported_ecosystem_yields_nothing(self) -> None:
        assert attest.extract_bundles("cargo", {"attestations": []}) == ()


class TestVerifyDegradation:
    """Every reason the check cannot run maps to UNVERIFIABLE, not INVALID."""

    def test_the_extra_absent_is_unverifiable(self, monkeypatch) -> None:
        monkeypatch.setattr(attest, "available", lambda: False)
        result = attest.verify(
            "{}", digest_hex="aa" * 32, algorithm="sha256", source_repo=("github.com", "o", "r")
        )
        assert result.outcome is Outcome.UNVERIFIABLE
        assert "extra" in result.detail

    def test_an_unsupported_algorithm_is_unverifiable(self, monkeypatch) -> None:
        monkeypatch.setattr(attest, "available", lambda: True)
        result = attest.verify(
            "{}", digest_hex="aa" * 16, algorithm="md5", source_repo=("github.com", "o", "r")
        )
        assert result.outcome is Outcome.UNVERIFIABLE

    def test_no_declared_repo_is_unverifiable(self, monkeypatch) -> None:
        monkeypatch.setattr(attest, "available", lambda: True)
        result = attest.verify("{}", digest_hex="aa" * 32, algorithm="sha256", source_repo=None)
        assert result.outcome is Outcome.UNVERIFIABLE

    def test_a_non_github_forge_is_unverifiable(self, monkeypatch) -> None:
        monkeypatch.setattr(attest, "available", lambda: True)
        result = attest.verify(
            "{}", digest_hex="aa" * 32, algorithm="sha256", source_repo=("gitlab.com", "o", "r")
        )
        assert result.outcome is Outcome.UNVERIFIABLE

    def test_an_unparseable_bundle_is_unverifiable(self, monkeypatch) -> None:
        # Uses the real sigstore Bundle parser: garbage in is refused, not a pass.
        pytest.importorskip("sigstore")
        monkeypatch.setattr(attest, "available", lambda: True)
        result = attest.verify(
            "not a bundle",
            digest_hex="aa" * 32,
            algorithm="sha256",
            source_repo=("github.com", "o", "r"),
        )
        assert result.outcome is Outcome.UNVERIFIABLE
        assert "did not parse" in result.detail


class TestVerifyOutcomeMapping:
    """With the bundle parser and verifier substituted, the outcome maps right."""

    @pytest.fixture(autouse=True)
    def _stub_bundle(self, monkeypatch):
        pytest.importorskip("sigstore")
        monkeypatch.setattr(attest, "available", lambda: True)
        monkeypatch.setattr("sigstore.models.Bundle.from_json", staticmethod(lambda raw: object()))

    def _run(self):
        return attest.verify(
            "{}", digest_hex="aa" * 32, algorithm="sha256", source_repo=("github.com", "o", "r")
        )

    def test_a_passing_verification_is_verified(self, monkeypatch) -> None:
        class FakeVerifier:
            def verify_artifact(self, hashed, bundle, policy) -> None:
                return None

        monkeypatch.setattr(
            "sigstore.verify.Verifier.production",
            staticmethod(lambda *, offline=False: FakeVerifier()),
        )
        assert self._run().outcome is Outcome.VERIFIED

    def test_a_rejected_signature_is_invalid(self, monkeypatch) -> None:
        from sigstore.verify.policy import VerificationError

        class FakeVerifier:
            def verify_artifact(self, hashed, bundle, policy) -> None:
                raise VerificationError("signature does not verify")

        monkeypatch.setattr(
            "sigstore.verify.Verifier.production",
            staticmethod(lambda *, offline=False: FakeVerifier()),
        )
        assert self._run().outcome is Outcome.INVALID

    def test_an_unreachable_trust_root_is_unverifiable(self, monkeypatch) -> None:
        from sigstore.errors import Error as SigstoreError

        def _raise(*, offline=False):
            raise SigstoreError("no trust root")

        monkeypatch.setattr("sigstore.verify.Verifier.production", staticmethod(_raise))
        assert self._run().outcome is Outcome.UNVERIFIABLE


class TestDsseBundlesTakeTheDsseRoute:
    """npm `--provenance` and PyPI PEP 740 publish DSSE envelopes, not message
    signatures, and the two are verified by different calls.

    `verify_artifact` requires a `messageSignature` and rejects a DSSE bundle
    with "Missing bundle message signature" however sound the attestation is --
    so routing provenance through it reported every honest publisher as a
    forgery. These tests assert the *route*, which a stub of one method alone
    cannot: a verifier here offers both, and fails if the wrong one is called.
    """

    DIGEST = "aa" * 32
    STATEMENT: ClassVar[dict] = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [{"name": "pkg:npm/x@1.0.0", "digest": {"sha256": DIGEST}}],
    }

    @pytest.fixture(autouse=True)
    def _stub_bundle(self, monkeypatch):
        pytest.importorskip("sigstore")
        monkeypatch.setattr(attest, "available", lambda: True)
        monkeypatch.setattr("sigstore.models.Bundle.from_json", staticmethod(lambda raw: object()))

    def _install(self, monkeypatch, verifier) -> None:
        monkeypatch.setattr(
            "sigstore.verify.Verifier.production",
            staticmethod(lambda *, offline=False: verifier),
        )

    def _verify(self, statement=None, digest=None):
        return attest.verify(
            json.dumps({"dsseEnvelope": {"payload": "x"}}),
            digest_hex=digest or self.DIGEST,
            algorithm="sha256",
            source_repo=("github.com", "o", "r"),
        )

    def test_a_dsse_bundle_is_verified_through_verify_dsse(self, monkeypatch) -> None:
        class FakeVerifier:
            def verify_artifact(self, hashed, bundle, policy):
                raise AssertionError("a DSSE bundle must not go through verify_artifact")

            def verify_dsse(self, bundle, policy):
                return (
                    "application/vnd.in-toto+json",
                    json.dumps(TestDsseBundlesTakeTheDsseRoute.STATEMENT).encode(),
                )

        self._install(monkeypatch, FakeVerifier())
        assert self._verify().outcome is Outcome.VERIFIED

    def test_a_signed_statement_about_other_bytes_is_invalid(self, monkeypatch) -> None:
        """`verify_dsse` proves who signed the envelope and nothing about which
        artefact the statement describes. Without the subject comparison this
        accepts a genuine attestation for another release as proof of this one."""

        class FakeVerifier:
            def verify_dsse(self, bundle, policy):
                return (
                    "application/vnd.in-toto+json",
                    json.dumps(TestDsseBundlesTakeTheDsseRoute.STATEMENT).encode(),
                )

        self._install(monkeypatch, FakeVerifier())
        result = self._verify(digest="bb" * 32)
        assert result.outcome is Outcome.INVALID
        assert "subject" in result.detail

    def test_a_subject_under_another_algorithm_cannot_be_compared(self, monkeypatch) -> None:
        class FakeVerifier:
            def verify_dsse(self, bundle, policy):
                statement = {
                    "subject": [{"name": "x", "digest": {"sha512": "cc" * 64}}],
                }
                return ("application/vnd.in-toto+json", json.dumps(statement).encode())

        self._install(monkeypatch, FakeVerifier())
        assert self._verify().outcome is Outcome.UNVERIFIABLE

    def test_an_unknown_payload_type_is_not_read(self, monkeypatch) -> None:
        class FakeVerifier:
            def verify_dsse(self, bundle, policy):
                return ("application/octet-stream", b"whatever")

        self._install(monkeypatch, FakeVerifier())
        assert self._verify().outcome is Outcome.UNVERIFIABLE

    def test_a_message_signature_bundle_still_uses_verify_artifact(self, monkeypatch) -> None:
        class FakeVerifier:
            def verify_dsse(self, bundle, policy):
                raise AssertionError("a message-signature bundle must not go through verify_dsse")

            def verify_artifact(self, hashed, bundle, policy) -> None:
                return None

        self._install(monkeypatch, FakeVerifier())
        result = attest.verify(
            json.dumps({"messageSignature": {"signature": "x"}}),
            digest_hex=self.DIGEST,
            algorithm="sha256",
            source_repo=("github.com", "o", "r"),
        )
        assert result.outcome is Outcome.VERIFIED
