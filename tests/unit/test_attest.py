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
        assert attest.AttestationDocuments.parse_integrity(value) == ("sha512", raw.hex())

    def test_pip_style_prefixed_hex(self) -> None:
        digest = "ab" * 32
        assert attest.AttestationDocuments.parse_integrity(f"sha256:{digest}") == ("sha256", digest)

    def test_a_wrong_length_digest_is_rejected(self) -> None:
        assert attest.AttestationDocuments.parse_integrity("sha256:abcd") is None

    def test_an_unknown_algorithm_is_rejected(self) -> None:
        assert attest.AttestationDocuments.parse_integrity("md5:" + "aa" * 16) is None

    def test_empty_and_shapeless_input_is_none(self) -> None:
        assert attest.AttestationDocuments.parse_integrity(None) is None
        assert attest.AttestationDocuments.parse_integrity("") is None
        assert attest.AttestationDocuments.parse_integrity("no-separator-here") is None


class TestExtractBundles:
    def test_npm_attestations_become_bundle_json(self) -> None:
        payload = {
            "attestations": [
                {"predicateType": "slsaprovenance", "bundle": {"a": 1}},
                {"predicateType": "publish", "bundle": {"b": 2}},
            ]
        }
        bundles = attest.AttestationDocuments.extract_bundles("npm", payload)
        assert [json.loads(b) for b in bundles] == [{"a": 1}, {"b": 2}]

    def test_an_npm_entry_without_a_bundle_is_skipped(self) -> None:
        payload = {"attestations": [{"predicateType": "x"}, {"bundle": {"ok": 1}}]}
        assert [
            json.loads(b) for b in attest.AttestationDocuments.extract_bundles("npm", payload)
        ] == [{"ok": 1}]

    def test_an_empty_or_shapeless_payload_yields_nothing(self) -> None:
        assert attest.AttestationDocuments.extract_bundles("npm", None) == ()
        assert attest.AttestationDocuments.extract_bundles("npm", {}) == ()
        assert (
            attest.AttestationDocuments.extract_bundles("npm", {"attestations": "not-a-list"}) == ()
        )

    def test_an_unsupported_ecosystem_yields_nothing(self) -> None:
        assert attest.AttestationDocuments.extract_bundles("cargo", {"attestations": []}) == ()


class TestVerifyDegradation:
    """Every reason the check cannot run maps to UNVERIFIABLE, not INVALID."""

    def test_the_extra_absent_is_unverifiable(self, monkeypatch) -> None:
        monkeypatch.setattr(attest.SigstoreVerification, "available", lambda: False)
        result = attest.SigstoreVerification.verify(
            "{}", digest_hex="aa" * 32, algorithm="sha256", source_repo=("github.com", "o", "r")
        )
        assert result.outcome is Outcome.UNVERIFIABLE
        assert "extra" in result.detail

    def test_an_unsupported_algorithm_is_unverifiable(self, monkeypatch) -> None:
        monkeypatch.setattr(attest.SigstoreVerification, "available", lambda: True)
        result = attest.SigstoreVerification.verify(
            "{}", digest_hex="aa" * 16, algorithm="md5", source_repo=("github.com", "o", "r")
        )
        assert result.outcome is Outcome.UNVERIFIABLE

    def test_no_declared_repo_is_unverifiable(self, monkeypatch) -> None:
        monkeypatch.setattr(attest.SigstoreVerification, "available", lambda: True)
        result = attest.SigstoreVerification.verify(
            "{}", digest_hex="aa" * 32, algorithm="sha256", source_repo=None
        )
        assert result.outcome is Outcome.UNVERIFIABLE

    def test_a_non_github_forge_is_unverifiable(self, monkeypatch) -> None:
        monkeypatch.setattr(attest.SigstoreVerification, "available", lambda: True)
        result = attest.SigstoreVerification.verify(
            "{}", digest_hex="aa" * 32, algorithm="sha256", source_repo=("gitlab.com", "o", "r")
        )
        assert result.outcome is Outcome.UNVERIFIABLE

    def test_an_unparseable_bundle_is_unverifiable(self, monkeypatch) -> None:
        # Uses the real sigstore Bundle parser: garbage in is refused, not a pass.
        pytest.importorskip("sigstore")
        monkeypatch.setattr(attest.SigstoreVerification, "available", lambda: True)
        result = attest.SigstoreVerification.verify(
            "not a bundle",
            digest_hex="aa" * 32,
            algorithm="sha256",
            source_repo=("github.com", "o", "r"),
        )
        assert result.outcome is Outcome.UNVERIFIABLE
        assert "did not parse" in result.detail


class TestTheSignerMustBeTheDeclaredRepository:
    """UNI-17: a valid signature from the wrong identity is not provenance. The policy handed to
    sigstore pins the certificate to GitHub Actions' issuer AND to the repository the package
    declares; a signature by any other repository fails that policy and is `INVALID`."""

    @pytest.mark.conformance("x", "x.provenance")
    @pytest.mark.conformance("npm", "UNI-17", "x.provenance")
    @pytest.mark.conformance("pypi", "UNI-17")
    def test_the_policy_names_the_declared_repository_and_issuer(self) -> None:
        pytest.importorskip("sigstore")
        built = attest.SigstoreVerification._identity_policy(("github.com", "acme", "app"))
        children = getattr(built, "_children", ())
        values = {type(c).__name__: getattr(c, "_value", None) for c in children}
        assert values.get("GitHubWorkflowRepository") == "acme/app"
        assert values.get("OIDCIssuer") == attest.GITHUB_OIDC_ISSUER

    @pytest.mark.conformance("npm", "UNI-17")
    @pytest.mark.conformance("pypi", "UNI-17")
    def test_no_declared_repository_is_never_verified(self) -> None:
        assert attest.SigstoreVerification._identity_policy(None) is None
        assert attest.SigstoreVerification._identity_policy(("gitlab.com", "acme", "app")) is None


class TestVerifyOutcomeMapping:
    """With the bundle parser and verifier substituted, the outcome maps right."""

    @pytest.fixture(autouse=True)
    def _stub_bundle(self, monkeypatch):
        pytest.importorskip("sigstore")
        monkeypatch.setattr(attest.SigstoreVerification, "available", lambda: True)
        monkeypatch.setattr("sigstore.models.Bundle.from_json", staticmethod(lambda raw: object()))

    def _run(self):
        return attest.SigstoreVerification.verify(
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

    @pytest.mark.conformance("npm", "UNI-17")
    @pytest.mark.conformance("pypi", "UNI-17")
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
        monkeypatch.setattr(attest.SigstoreVerification, "available", lambda: True)
        monkeypatch.setattr("sigstore.models.Bundle.from_json", staticmethod(lambda raw: object()))

    def _install(self, monkeypatch, verifier) -> None:
        monkeypatch.setattr(
            "sigstore.verify.Verifier.production",
            staticmethod(lambda *, offline=False: verifier),
        )

    def _verify(self, statement=None, digest=None):
        return attest.SigstoreVerification.verify(
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

    @pytest.mark.conformance("npm", "UNI-17")
    @pytest.mark.conformance("pypi", "UNI-17")
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

    @pytest.mark.conformance("x", "x.provenance")
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
        result = attest.SigstoreVerification.verify(
            json.dumps({"messageSignature": {"signature": "x"}}),
            digest_hex=self.DIGEST,
            algorithm="sha256",
            source_repo=("github.com", "o", "r"),
        )
        assert result.outcome is Outcome.VERIFIED


class Certificates:
    """A throwaway self-signed certificate carrying Fulcio's issuer extension, made in the test:
    `SigstoreVerification.issuer` reads the extension and nothing else of it."""

    @staticmethod
    def with_issuer(issuer: str, *, legacy: bool = False):
        pytest.importorskip("cryptography")
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "conformance")])
        encoded = issuer.encode()
        oid = (
            attest.SigstoreVerification._ISSUER_V1
            if legacy
            else attest.SigstoreVerification._ISSUER_V2
        )
        value = encoded if legacy else bytes([0x0C, len(encoded)]) + encoded
        now = datetime.datetime.now(datetime.UTC)
        return (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(minutes=10))
            .add_extension(
                x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), value), critical=False
            )
            .sign(key, hashes.SHA256())
        )


class TestMavenCentralSignatures:
    """Maven Central's Sigstore bundles (`<jar>.sigstore.json`): a signature over the jar itself,
    bound to the jar's SHA-256 the build recorded (`.mvn/checksums/`) and to the repository the
    published POM declares. A bundle a person signed with an email identity is honest and
    common on Central, and is unverifiable here -- never reported as a forgery."""

    DIGEST = "bb" * 32

    @pytest.fixture(autouse=True)
    def _available(self, monkeypatch):
        pytest.importorskip("sigstore")
        monkeypatch.setattr(attest.SigstoreVerification, "available", lambda: True)

    def _bundle(self, monkeypatch, issuer: str | None) -> None:
        certificate = Certificates.with_issuer(issuer) if issuer else None

        class FakeBundle:
            @property
            def signing_certificate(self):
                if certificate is None:
                    raise ValueError("no certificate")
                return certificate

        monkeypatch.setattr(
            "sigstore.models.Bundle.from_json", staticmethod(lambda raw: FakeBundle())
        )

    def _verifier(self, monkeypatch, *, rejects: bool) -> list[str]:
        from sigstore.verify.policy import VerificationError

        called: list[str] = []

        class FakeVerifier:
            def verify_dsse(self, bundle, policy):
                raise AssertionError("a Maven bundle signs the jar, not a DSSE envelope")

            def verify_artifact(self, hashed, bundle, policy) -> None:
                called.append(hashed.digest.hex())
                if rejects:
                    raise VerificationError("signature does not verify")

        monkeypatch.setattr(
            "sigstore.verify.Verifier.production",
            staticmethod(lambda *, offline=False: FakeVerifier()),
        )
        return called

    def _verify(self):
        return attest.SigstoreVerification.verify(
            json.dumps({"messageSignature": {"signature": "x"}}),
            digest_hex=self.DIGEST,
            algorithm="sha256",
            source_repo=("github.com", "acme", "lib"),
        )

    @pytest.mark.conformance("maven", "UNI-17", "x.provenance")
    @pytest.mark.conformance("gradle", "UNI-17")
    @pytest.mark.parametrize("ecosystem", ["maven", "gradle"])
    def test_the_bundle_is_extracted_from_the_registry_document(self, ecosystem) -> None:
        """A Gradle build's dependencies are Maven Central artefacts with the same bundles."""
        bundle = {
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "messageSignature": {},
        }
        assert attest.AttestationDocuments.extract_bundles(ecosystem, {"bundle": bundle}) == (
            json.dumps(bundle),
        )
        assert (
            attest.AttestationDocuments.extract_bundles(ecosystem, {"bundle": "not a bundle"}) == ()
        )

    @pytest.mark.conformance("maven", "UNI-17")
    def test_a_workflow_signature_over_the_jar_digest_verifies(self, monkeypatch) -> None:
        self._bundle(monkeypatch, attest.GITHUB_OIDC_ISSUER)
        called = self._verifier(monkeypatch, rejects=False)
        assert self._verify().outcome is Outcome.VERIFIED
        assert called == [self.DIGEST], (
            "the signature was not checked against the recorded jar digest"
        )

    @pytest.mark.conformance("maven", "UNI-17")
    def test_a_workflow_signature_that_does_not_verify_is_invalid(self, monkeypatch) -> None:
        self._bundle(monkeypatch, attest.GITHUB_OIDC_ISSUER)
        self._verifier(monkeypatch, rejects=True)
        assert self._verify().outcome is Outcome.INVALID

    @pytest.mark.conformance("maven", "UNI-17")
    @pytest.mark.parametrize("legacy", [False, True])
    def test_a_person_signed_bundle_is_unverifiable_not_invalid(self, monkeypatch, legacy) -> None:
        certificate = Certificates.with_issuer("https://accounts.google.com", legacy=legacy)
        assert (
            attest.SigstoreVerification.issuer(
                type("B", (), {"signing_certificate": certificate})()
            )
            == "https://accounts.google.com"
        )
        self._bundle(monkeypatch, "https://accounts.google.com")
        called = self._verifier(monkeypatch, rejects=True)
        result = self._verify()
        assert result.outcome is Outcome.UNVERIFIABLE and "accounts.google.com" in result.detail
        assert called == [], "a policy check against the repository would call this a forgery"

    @pytest.mark.conformance("maven", "UNI-17")
    @pytest.mark.conformance("gradle", "UNI-17")
    @pytest.mark.parametrize("ecosystem", ["maven", "gradle"])
    def test_the_bundle_is_fetched_from_central_only(self, monkeypatch, ecosystem) -> None:
        from cordon_scanner.intel.registry_client import RegistryClient

        asked: list[str] = []
        monkeypatch.setattr(
            RegistryClient,
            "_fetch",
            staticmethod(lambda url, accept="": asked.append(url) or {"messageSignature": {}}),
        )
        payload = RegistryClient.attestation_payload(ecosystem, "com.acme:lib", "1.2.0")
        assert payload == {"bundle": {"messageSignature": {}}}
        assert asked == [
            "https://repo.maven.apache.org/maven2/com/acme/lib/1.2.0/lib-1.2.0.jar.sigstore.json"
        ]
        assert RegistryClient.attestation_payload(ecosystem, "com.acme:../lib", "1.2.0") is None

    @pytest.mark.conformance("maven", "UNI-17")
    def test_the_source_repository_comes_from_the_published_pom(self, monkeypatch) -> None:
        from cordon_scanner.intel.more_registries import MoreRegistries

        pom = "<project><url>https://acme.example</url><scm><url>https://github.com/acme/lib</url></scm></project>"
        monkeypatch.setattr(MoreRegistries, "_text", staticmethod(lambda url: pom))
        assert (
            MoreRegistries._maven_scm("https://repo.maven.apache.org/x.pom")
            == "https://github.com/acme/lib"
        )
        monkeypatch.setattr(
            MoreRegistries,
            "_text",
            staticmethod(lambda url: '<!DOCTYPE p [<!ENTITY e "x">]><project/>'),
        )
        assert MoreRegistries._maven_scm("https://repo.maven.apache.org/x.pom") is None

    @pytest.mark.conformance("maven", "UNI-17")
    @pytest.mark.conformance("gradle", "UNI-17")
    def test_a_classified_artefact_is_not_checked_against_the_plain_jar(self, monkeypatch) -> None:
        from cordon_scanner.core.models import Dependency
        from cordon_scanner.detect.base import GraphUnit
        from cordon_scanner.detect.provenance import ProvenanceDetector
        from cordon_scanner.intel.registry_client import RegistryClient

        asked: list[str] = []

        def facts(ecosystem, name, version):
            asked.append(name)
            raise __import__(
                "cordon_scanner.intel.registry_client", fromlist=["RegistryError"]
            ).RegistryError("stub")

        monkeypatch.setattr(RegistryClient, "facts", staticmethod(facts))
        plain = Dependency(
            purl="pkg:maven/com.acme:lib@1.0",
            ecosystem="maven",
            name="com.acme:lib",
            version="1.0",
            direct=True,
        )
        native = Dependency(
            purl="pkg:maven/com.acme:native@1.0?classifier=linux-x86_64",
            ecosystem="maven",
            name="com.acme:native",
            version="1.0",
            direct=True,
        )
        from dataclasses import replace

        ctx = type("Ctx", (), {"offline": False, "out_of_time": lambda self: False})()
        list(ProvenanceDetector().inspect(GraphUnit(dependencies=(plain, native)), ctx))
        assert asked == ["com.acme:lib"]
        asked.clear()
        gradle = (replace(plain, ecosystem="gradle"), replace(native, ecosystem="gradle"))
        list(ProvenanceDetector().inspect(GraphUnit(dependencies=gradle), ctx))
        assert asked == ["com.acme:lib"]


class TestRubyGemsAttestations:
    """RubyGems.org publishes the Sigstore bundles of a version pushed through trusted publishing at
    `/api/v1/attestations/<name>-<version>.json`, an array; they are verified against the SHA-256
    Bundler records in Gemfile.lock's CHECKSUMS, through the same verifier as npm's and PyPI's."""

    @pytest.mark.conformance("rubygems", "UNI-17")
    def test_every_bundle_in_the_array_is_extracted(self) -> None:
        first, second = {"dsseEnvelope": {"payload": "a"}}, {"messageSignature": {}}
        assert attest.AttestationDocuments.extract_bundles(
            "rubygems", {"bundles": [first, "junk", second]}
        ) == (
            json.dumps(first),
            json.dumps(second),
        )
        assert (
            attest.AttestationDocuments.extract_bundles("rubygems", {"bundles": "not a list"}) == ()
        )

    @pytest.mark.conformance("rubygems", "UNI-17")
    def test_the_documented_endpoint_on_rubygems_org_only(self, monkeypatch) -> None:
        from cordon_scanner.intel.registry_client import RegistryClient

        asked: list[tuple[str, bool]] = []

        def fetch(url, accept="", array=False):
            asked.append((url, array))
            return {"items": [{"dsseEnvelope": {}}]}

        monkeypatch.setattr(RegistryClient, "_fetch", staticmethod(fetch))
        assert RegistryClient.attestation_payload("rubygems", "rack", "3.1.8") == {
            "bundles": [{"dsseEnvelope": {}}]
        }
        assert asked == [("https://rubygems.org/api/v1/attestations/rack-3.1.8.json", True)]
        assert RegistryClient.attestation_payload("rubygems", "../etc", "1") is None
        assert RegistryClient.attestation_payload("rubygems", "rack", "1/2") is None

    @pytest.mark.conformance("rubygems", "UNI-17")
    def test_no_bundles_is_not_attested(self, monkeypatch) -> None:
        from cordon_scanner.intel.registry_client import RegistryClient

        monkeypatch.setattr(
            RegistryClient,
            "_fetch",
            staticmethod(lambda url, accept="", array=False: {"items": []}),
        )
        assert RegistryClient.attestation_payload("rubygems", "rack", "3.1.8") is None

    @pytest.mark.conformance("rubygems", "UNI-17")
    def test_a_locked_checksum_is_the_digest_bound(self) -> None:
        digest = "ab" * 32
        assert attest.AttestationDocuments.parse_integrity(f"sha256:{digest}") == ("sha256", digest)


class TestWhatIsNotARejection:
    """Two answers sigstore gives that are not a forged attestation, found on real npm lockfiles:
    39 packages' genuine attestations, and typedoc's, had been reported VULNERABLE.PROVENANCE.INVALID."""

    @staticmethod
    def certificate(repository: str):
        pytest.importorskip("cryptography")
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "conformance")])
        now = datetime.datetime.now(datetime.UTC)
        return (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(minutes=10))
            # GitHub Actions' workflow-repository claim, raw bytes, as Fulcio writes it.
            .add_extension(
                x509.UnrecognizedExtension(
                    x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.5"), repository.encode()
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

    def test_an_entry_sigstore_does_not_support_is_unverifiable(self) -> None:
        pytest.importorskip("sigstore")
        from sigstore.verify.policy import VerificationError  # type: ignore[attr-defined]

        unsupported = VerificationError(
            "Integrated time only supported for dsse/hashedrekord 0.0.1 types"
        )
        assert attest.SigstoreVerification._refused(unsupported).outcome is Outcome.UNVERIFIABLE
        forged = VerificationError("Signature is invalid for input")
        assert attest.SigstoreVerification._refused(forged).outcome is Outcome.INVALID

    def test_the_repository_is_compared_without_regard_to_case(self) -> None:
        pytest.importorskip("sigstore")
        from sigstore.verify.policy import VerificationError  # type: ignore[attr-defined]

        check = attest.SigstoreVerification._repository_policy("TypeStrong/TypeDoc")
        check.verify(self.certificate("TypeStrong/typedoc"))
        with pytest.raises(VerificationError, match="does not match"):
            check.verify(self.certificate("TypeStrong/typedoc-fork"))
