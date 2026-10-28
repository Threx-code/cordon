"""The provenance verifier, on real attestations and on every way one can fail.

The cryptography is Cordon's own (`sigstore_bundle`), so it is tested for real here: one genuine
public attestation of each shape the registries publish (`tests/unit/data/sigstore`) verifies
against the trust material Cordon pins, with no network, and each fails as it should when the
digest, the repository or the identity is not the one asked about. Every reason a check cannot
run is `UNVERIFIABLE`; only a cryptographic, identity or subject rejection is `INVALID`.
"""

from __future__ import annotations

import datetime as dt
import json
from typing import Any, ClassVar

import pytest

from cordon_scanner.intel.provenance import attest, sigstore_bundle
from cordon_scanner.intel.provenance.attest import Outcome
from cordon_scanner.intel.provenance.x509 import Certificate
from support import ROOT as REPO


class Fixtures:
    DIR = REPO / "tests" / "unit" / "data" / "sigstore"

    @staticmethod
    def load(name: str) -> dict[str, Any]:
        return json.loads((Fixtures.DIR / f"{name}.json").read_text(encoding="utf-8"))

    @staticmethod
    def npm(name: str) -> tuple[str, str, tuple[str, str, str] | None]:
        """A fixture's bundle JSON, its sha512 subject digest, and the repository its certificate
        names (None for a registry-signed bundle)."""
        fixture = Fixtures.load(name)
        bundle = fixture["bundle"]
        material = bundle["verificationMaterial"]
        raw = (
            material.get("certificate")
            or (material.get("x509CertificateChain") or {}).get("certificates", [None])[0]
        )
        repository = None
        if raw is not None:
            import base64

            certificate = Certificate.from_der(base64.b64decode(raw["rawBytes"]))
            named = certificate.extension_text("1.3.6.1.4.1.57264.1.5", der_string=False)
            assert named is not None
            owner, name_ = named.split("/")
            repository = ("github.com", owner, name_)
        return json.dumps(bundle), fixture["subject_digest"]["sha512"], repository

    @staticmethod
    def certificate() -> Certificate:
        import base64

        bundle = Fixtures.load("npm-provenance-dsse")["bundle"]
        return Certificate.from_der(
            base64.b64decode(bundle["verificationMaterial"]["certificate"]["rawBytes"])
        )


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

    REPO: ClassVar[tuple[str, str, str]] = ("github.com", "o", "r")

    def test_verification_needs_no_extra(self) -> None:
        assert attest.SigstoreVerification.available() is True

    def test_an_unsupported_algorithm_is_unverifiable(self) -> None:
        result = attest.SigstoreVerification.verify(
            "{}", digest_hex="aa" * 16, algorithm="md5", source_repo=self.REPO
        )
        assert result.outcome is Outcome.UNVERIFIABLE

    def test_no_declared_repo_is_unverifiable(self) -> None:
        result = attest.SigstoreVerification.verify(
            "{}", digest_hex="aa" * 32, algorithm="sha256", source_repo=None
        )
        assert result.outcome is Outcome.UNVERIFIABLE

    def test_a_non_github_forge_is_unverifiable(self) -> None:
        result = attest.SigstoreVerification.verify(
            "{}", digest_hex="aa" * 32, algorithm="sha256", source_repo=("gitlab.com", "o", "r")
        )
        assert result.outcome is Outcome.UNVERIFIABLE

    def test_an_unparseable_bundle_is_unverifiable(self) -> None:
        result = attest.SigstoreVerification.verify(
            "not a bundle", digest_hex="aa" * 32, algorithm="sha256", source_repo=self.REPO
        )
        assert result.outcome is Outcome.UNVERIFIABLE
        assert "could not be checked" in result.detail


class TestRealAttestations:
    """One genuine attestation of each shape, verified offline against the pinned trust root."""

    @pytest.mark.conformance("x", "x.provenance")
    @pytest.mark.conformance("npm", "UNI-17", "x.provenance")
    @pytest.mark.parametrize("name", ["npm-provenance-dsse", "npm-provenance-v0.1"])
    def test_npm_provenance_verifies(self, name: str) -> None:
        bundle, digest, repository = Fixtures.npm(name)
        result = attest.SigstoreVerification.verify(
            bundle, digest_hex=digest, algorithm="sha512", source_repo=repository
        )
        assert result.outcome is Outcome.VERIFIED, result.detail

    def test_an_intoto_entry_sigstore_python_declines_is_verified(self) -> None:
        """npm's provenance logged as Rekor `intoto` 0.0.2 until 2025, which sigstore-python
        will not check (39 genuine attestations unverifiable on real lockfiles); this verifier
        reads them."""
        bundle, digest, repository = Fixtures.npm("npm-provenance-intoto")
        result = attest.SigstoreVerification.verify(
            bundle, digest_hex=digest, algorithm="sha512", source_repo=repository
        )
        assert result.outcome is Outcome.VERIFIED, result.detail

    def test_npm_publish_attestation_is_verified_but_names_no_repository(self) -> None:
        bundle, digest, _ = Fixtures.npm("npm-publish")
        result = attest.SigstoreVerification.verify(
            bundle, digest_hex=digest, algorithm="sha512", source_repo=("github.com", "o", "r")
        )
        assert result.outcome is Outcome.UNVERIFIABLE
        assert "registry" in result.detail

    @pytest.mark.conformance("npm", "UNI-17")
    @pytest.mark.conformance("pypi", "UNI-17")
    def test_a_signed_statement_about_other_bytes_is_invalid(self) -> None:
        """The envelope's signature says who signed the statement and nothing about which
        artefact it describes: a genuine attestation of another release is not proof of this one."""
        bundle, _, repository = Fixtures.npm("npm-provenance-dsse")
        result = attest.SigstoreVerification.verify(
            bundle, digest_hex="cd" * 64, algorithm="sha512", source_repo=repository
        )
        assert result.outcome is Outcome.INVALID
        assert "subject" in result.detail

    def test_a_subject_under_another_algorithm_cannot_be_compared(self) -> None:
        bundle, _, repository = Fixtures.npm("npm-provenance-dsse")
        result = attest.SigstoreVerification.verify(
            bundle, digest_hex="ab" * 32, algorithm="sha256", source_repo=repository
        )
        assert result.outcome is Outcome.UNVERIFIABLE

    @pytest.mark.conformance("pypi", "UNI-17", "x.provenance")
    def test_pypi_pep740_provenance_verifies(self) -> None:
        fixture = Fixtures.load("pypi-pep740")
        bundles = attest.AttestationDocuments.extract_bundles("pypi", fixture["provenance"])
        assert bundles
        owner, name = fixture["repository"].split("/")
        results = [
            attest.SigstoreVerification.verify(
                b,
                digest_hex=fixture["sha256"],
                algorithm="sha256",
                source_repo=("github.com", owner, name),
            )
            for b in bundles
        ]
        assert any(r.outcome is Outcome.VERIFIED for r in results), [r.detail for r in results]

    def test_every_tampered_byte_of_the_envelope_is_refused(self) -> None:
        import base64

        bundle, digest, repository = Fixtures.npm("npm-provenance-dsse")
        document = json.loads(bundle)
        payload = bytearray(base64.b64decode(document["dsseEnvelope"]["payload"]))
        for at in range(0, len(payload), max(1, len(payload) // 64)):
            tampered = bytearray(payload)
            tampered[at] ^= 0x20
            document["dsseEnvelope"]["payload"] = base64.b64encode(bytes(tampered)).decode()
            result = attest.SigstoreVerification.verify(
                json.dumps(document), digest_hex=digest, algorithm="sha512", source_repo=repository
            )
            assert result.outcome is not Outcome.VERIFIED, at


class TestTheSignerMustBeTheDeclaredRepository:
    """UNI-17: a valid signature from the wrong identity is not provenance. The certificate must
    come from GitHub Actions' issuer AND name the repository the package declares."""

    @pytest.mark.conformance("npm", "UNI-17")
    @pytest.mark.conformance("pypi", "UNI-17")
    def test_another_repository_is_invalid_and_named(self) -> None:
        bundle, digest, repository = Fixtures.npm("npm-provenance-dsse")
        assert repository is not None
        result = attest.SigstoreVerification.verify(
            bundle,
            digest_hex=digest,
            algorithm="sha512",
            source_repo=("github.com", "evil", "fork"),
        )
        assert result.outcome is Outcome.INVALID
        assert "GitHubWorkflowRepository does not match" in result.detail
        assert f"{repository[1]}/{repository[2]}" in result.detail

    def test_the_repository_is_compared_without_regard_to_case(self) -> None:
        """typedoc declares `TypeStrong/TypeDoc`; its certificates say `TypeStrong/typedoc`."""
        bundle, digest, repository = Fixtures.npm("npm-provenance-dsse")
        assert repository is not None
        shouted = (repository[0], repository[1].upper(), repository[2].upper())
        result = attest.SigstoreVerification.verify(
            bundle, digest_hex=digest, algorithm="sha512", source_repo=shouted
        )
        assert result.outcome is Outcome.VERIFIED

    @pytest.mark.conformance("npm", "UNI-17")
    @pytest.mark.conformance("pypi", "UNI-17")
    def test_no_declared_repository_is_never_verified(self) -> None:
        assert attest.SigstoreVerification._repository(None) is None
        assert attest.SigstoreVerification._repository(("gitlab.com", "acme", "app")) is None
        assert attest.SigstoreVerification._repository(("github.com", "acme", "app")) == "acme/app"


class TestVerifyOutcomeMapping:
    """What the verifier concluded, mapped to the outcome the detector acts on."""

    def _with(self, monkeypatch, outcome) -> attest.Result:
        def verify(self, bundle_json, *, digest_hex=None, algorithm=None):
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        monkeypatch.setattr(sigstore_bundle.BundleVerifier, "verify", verify)
        return attest.SigstoreVerification.verify(
            "{}", digest_hex="aa" * 32, algorithm="sha256", source_repo=("github.com", "o", "r")
        )

    @pytest.mark.conformance("npm", "UNI-17")
    @pytest.mark.conformance("pypi", "UNI-17")
    def test_a_rejected_bundle_is_invalid(self, monkeypatch) -> None:
        result = self._with(monkeypatch, sigstore_bundle.Rejected("signature does not verify"))
        assert result.outcome is Outcome.INVALID

    def test_a_bundle_that_cannot_be_checked_is_unverifiable(self, monkeypatch) -> None:
        result = self._with(monkeypatch, sigstore_bundle.BundleError("unknown log"))
        assert result.outcome is Outcome.UNVERIFIABLE

    @pytest.mark.conformance("maven", "UNI-17")
    @pytest.mark.parametrize("legacy", [False, True])
    def test_a_person_signed_bundle_is_unverifiable_not_invalid(self, monkeypatch, legacy) -> None:
        """Signed through a Google or Microsoft login: honest, common on Maven Central, and tied
        to no source repository -- a question this check cannot answer, not a forgery."""
        certificate = Fixtures.certificate()
        wanted = (
            attest.SigstoreVerification._ISSUER_V1
            if legacy
            else attest.SigstoreVerification._ISSUER_V2
        )

        def text(self, oid, *, der_string):
            return "https://accounts.google.com" if oid == wanted else None

        monkeypatch.setattr(Certificate, "extension_text", text)
        verified = sigstore_bundle.Verified(certificate, None, None, None, dt.datetime.now(dt.UTC))
        result = self._with(monkeypatch, verified)
        assert result.outcome is Outcome.UNVERIFIABLE and "accounts.google.com" in result.detail

    def test_an_unknown_payload_type_is_not_read(self, monkeypatch) -> None:
        verified = sigstore_bundle.Verified(
            Fixtures.certificate(), None, "application/octet-stream", b"x", dt.datetime.now(dt.UTC)
        )
        bundle, _, repository = Fixtures.npm("npm-provenance-dsse")
        monkeypatch.setattr(
            sigstore_bundle.BundleVerifier,
            "verify",
            lambda self, b, digest_hex=None, algorithm=None: verified,
        )
        assert repository is not None
        result = attest.SigstoreVerification.verify(
            bundle, digest_hex="aa" * 32, algorithm="sha256", source_repo=repository
        )
        assert result.outcome is Outcome.UNVERIFIABLE


class TestMavenCentralSignatures:
    """Maven Central's Sigstore bundles (`<jar>.sigstore.json`): a signature over the jar itself,
    bound to the jar's SHA-256 the build recorded (`.mvn/checksums/`) and to the repository the
    published POM declares."""

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

    def _verify(self, digest: str) -> attest.Result:
        fixture = Fixtures.load("maven-message-signature")
        owner, name = fixture["repository"].split("/")
        return attest.SigstoreVerification.verify(
            json.dumps(fixture["bundle"]),
            digest_hex=digest,
            algorithm="sha256",
            source_repo=("github.com", owner, name),
        )

    @pytest.mark.conformance("maven", "UNI-17")
    def test_a_workflow_signature_over_the_jar_digest_verifies(self) -> None:
        result = self._verify(Fixtures.load("maven-message-signature")["sha256"])
        assert result.outcome is Outcome.VERIFIED, result.detail

    @pytest.mark.conformance("maven", "UNI-17")
    def test_a_signature_over_another_jar_is_invalid(self) -> None:
        assert self._verify("00" * 32).outcome is Outcome.INVALID

    @pytest.mark.conformance("maven", "UNI-17")
    @pytest.mark.conformance("gradle", "UNI-17")
    @pytest.mark.parametrize("ecosystem", ["maven", "gradle"])
    def test_the_bundle_is_fetched_from_central_only(self, monkeypatch, ecosystem) -> None:
        from cordon_scanner.intel.registries.registry_client import RegistryClient

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
        from cordon_scanner.intel.registries.more_registries import MoreRegistries
        from cordon_scanner.intel.registries.package_registries import PackageRegistries

        pom = "<project><url>https://acme.example</url><scm><url>https://github.com/acme/lib</url></scm></project>"
        monkeypatch.setattr(MoreRegistries, "_text", staticmethod(lambda url: pom))
        assert (
            PackageRegistries.maven_scm("https://repo.maven.apache.org/x.pom")
            == "https://github.com/acme/lib"
        )
        monkeypatch.setattr(
            MoreRegistries,
            "_text",
            staticmethod(lambda url: '<!DOCTYPE p [<!ENTITY e "x">]><project/>'),
        )
        assert PackageRegistries.maven_scm("https://repo.maven.apache.org/x.pom") is None

    @pytest.mark.conformance("maven", "UNI-17")
    @pytest.mark.conformance("gradle", "UNI-17")
    def test_a_classified_artefact_is_not_checked_against_the_plain_jar(self, monkeypatch) -> None:
        from cordon_scanner.detect.base import GraphUnit
        from cordon_scanner.detect.supply.provenance import ProvenanceDetector
        from cordon_scanner.foundation.results import Dependency
        from cordon_scanner.intel.registries.registry_client import RegistryClient

        asked: list[str] = []

        def facts(ecosystem, name, version):
            asked.append(name)
            raise __import__(
                "cordon_scanner.intel.registries.registry_client", fromlist=["RegistryError"]
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
        from cordon_scanner.intel.registries.registry_client import RegistryClient

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
        from cordon_scanner.intel.registries.registry_client import RegistryClient

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


class TestTheAttestationOfThePinnedFile:
    """PyPI attests each file of a release on its own. Probed on a real uv.lock, 38 packages'
    genuine attestations were reported invalid: the wheel's, listed first, checked against the
    sdist uv pins."""

    SDIST = "e" * 64
    WHEEL = "2" * 64

    def payload(self, monkeypatch, digest: str | None):
        from cordon_scanner.intel.registries.registry_client import RegistryClient

        simple = {
            "files": [
                {
                    "filename": "colorlog-6.10.1-py3-none-any.whl",
                    "hashes": {"sha256": self.WHEEL},
                    "provenance": "https://pypi.org/integrity/colorlog/6.10.1/wheel/provenance",
                },
                {
                    "filename": "colorlog-6.10.1.tar.gz",
                    "hashes": {"sha256": self.SDIST},
                    "provenance": "https://pypi.org/integrity/colorlog/6.10.1/sdist/provenance",
                },
            ]
        }
        monkeypatch.setattr(RegistryClient, "_fetch", staticmethod(lambda url, accept="": simple))
        monkeypatch.setattr(
            RegistryClient, "_fetch_from_allowlist", staticmethod(lambda url, eco: {"from": url})
        )
        return RegistryClient.attestation_payload("pypi", "colorlog", "6.10.1", digest)

    @pytest.mark.conformance("pypi", "UNI-17")
    def test_the_file_whose_hash_was_pinned_is_the_one_asked_about(self, monkeypatch) -> None:
        assert self.payload(monkeypatch, self.SDIST)["from"].endswith("/sdist/provenance")
        assert self.payload(monkeypatch, self.WHEEL)["from"].endswith("/wheel/provenance")

    def test_a_pin_no_file_of_the_version_has_asks_about_none(self, monkeypatch) -> None:
        assert self.payload(monkeypatch, "0" * 64) is None


class TestARenamedRepository:
    """filelock declares tox-dev/py-filelock; GitHub renamed it tox-dev/filelock, the name its
    certificates carry."""

    def test_github_resolves_the_old_name_to_the_new(self, monkeypatch) -> None:
        import io
        import json as _json
        import urllib.request

        from cordon_scanner.intel.provenance.github_repository import GitHubRepository

        asked: list[str] = []

        class Opener:
            def open(self, request, timeout):
                asked.append(request.full_url)
                return io.BytesIO(_json.dumps({"full_name": "tox-dev/filelock"}).encode())

        monkeypatch.setattr(urllib.request, "build_opener", lambda *handlers: Opener())
        assert GitHubRepository.current("tox-dev", "py-filelock") == ("tox-dev", "filelock")
        assert asked == ["https://api.github.com/repos/tox-dev/py-filelock"]

    def test_a_redirect_off_the_api_is_not_followed(self) -> None:
        from cordon_scanner.intel.provenance.github_repository import _ApiRedirects

        handler = _ApiRedirects()
        assert handler.redirect_request(None, None, 301, "", {}, "https://example.com/x") is None

    def test_the_detector_verifies_against_the_current_name(self, monkeypatch) -> None:
        from cordon_scanner.detect.supply.provenance import ProvenanceDetector
        from cordon_scanner.intel.provenance.github_repository import GitHubRepository

        monkeypatch.setattr(
            GitHubRepository, "current", staticmethod(lambda owner, name: ("tox-dev", "filelock"))
        )
        refused = attest.Result(
            Outcome.INVALID,
            "verification failed: Certificate's GitHubWorkflowRepository does not match "
            "(got 'tox-dev/filelock', expected 'tox-dev/py-filelock')",
        )
        assert ProvenanceDetector._renamed(("github.com", "tox-dev", "py-filelock"), [refused]) == (
            "github.com",
            "tox-dev",
            "filelock",
        )
        # A forgery is not retried under another name, nor a repository GitHub names the same.
        forged = attest.Result(Outcome.INVALID, "verification failed: Signature is invalid")
        assert (
            ProvenanceDetector._renamed(("github.com", "tox-dev", "py-filelock"), [forged]) is None
        )
        monkeypatch.setattr(
            GitHubRepository,
            "current",
            staticmethod(lambda owner, name: ("Tox-Dev", "PY-filelock")),
        )
        assert (
            ProvenanceDetector._renamed(("github.com", "tox-dev", "py-filelock"), [refused]) is None
        )
