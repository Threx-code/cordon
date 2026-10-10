"""Bazel Central Registry modules against their build attestations (`intel/bazel_provenance`).

Offline: the registry, the release host and the sigstore verifier are stood in for, so what is
tested is the decision -- which file is verified against which pinned digest, which repository must
have signed it, and what each answer means. The cryptography is `attest.SigstoreVerification`'s; it
was checked against BCR's real aspect_rules_js 3.5.1 attestations when this was written: both
bundles verify for aspect-build/rules_js, and the same bundle is rejected for another digest and
for another repository.
"""

from __future__ import annotations

import base64
import hashlib
import json
import urllib.error

import pytest

from cordon_scanner.intel import attest
from cordon_scanner.intel.bazel_provenance import BazelProvenance

ARCHIVE = hashlib.sha256(b"the module archive").digest()
RELEASE = "https://github.com/acme/rules_x/releases/download/v1.0.0"
SOURCE = json.dumps(
    {
        "integrity": "sha256-" + base64.b64encode(ARCHIVE).decode(),
        "url": f"{RELEASE}/rules_x-v1.0.0.tar.gz",
    }
).encode()
SOURCE_PIN = "sha256:" + hashlib.sha256(SOURCE).hexdigest()
ARCHIVE_PIN = "sha256-" + base64.b64encode(ARCHIVE).decode()
BUNDLE = b'{"bundle": 1}\n'


class Registry:
    @staticmethod
    def entry(url: str, body: bytes = BUNDLE) -> dict[str, str]:
        """An attestations.json entry: the bundle's URL and its hash."""
        return {
            "url": url,
            "integrity": "sha256-" + base64.b64encode(hashlib.sha256(body).digest()).decode(),
        }

    def __init__(
        self,
        monkeypatch,
        *,
        attestations: dict | None = None,
        repository: str = "github:acme/rules_x",
        released: bytes = BUNDLE,
        verdict=attest.Outcome.VERIFIED,
    ):
        self.verified: list[tuple[str, tuple]] = []
        listed = (
            attestations
            if attestations is not None
            else {
                "source.json": Registry.entry(f"{RELEASE}/source.json.intoto.jsonl"),
                "MODULE.bazel": Registry.entry(f"{RELEASE}/MODULE.bazel.intoto.jsonl"),
                "rules_x-v1.0.0.tar.gz": Registry.entry(
                    f"{RELEASE}/rules_x-v1.0.0.tar.gz.intoto.jsonl"
                ),
            }
        )
        files = {
            "rules_x/1.0.0/attestations.json": json.dumps(
                {
                    "mediaType": "application/vnd.build.bazel.registry.attestation+json;version=1.0.0",
                    "attestations": listed,
                }
            ).encode(),
            "rules_x/1.0.0/source.json": SOURCE,
            "rules_x/metadata.json": json.dumps({"repository": [repository]}).encode(),
        }

        def get(url: str) -> bytes:
            if url.startswith("https://bcr.bazel.build/modules/"):
                found = files.get(url.removeprefix("https://bcr.bazel.build/modules/"))
                if found is None:
                    raise urllib.error.HTTPError(url, 404, "not found", None, None)  # type: ignore[arg-type]
                return found
            return released

        def verify(bundle, *, digest_hex, algorithm, source_repo, offline=False):
            self.verified.append((digest_hex, source_repo))
            return attest.Result(verdict, "stood in")

        monkeypatch.setattr(BazelProvenance, "_get", staticmethod(get))
        monkeypatch.setattr(attest.SigstoreVerification, "verify", staticmethod(verify))


class TestBazelModules:
    @pytest.mark.conformance("bazel", "UNI-17")
    def test_a_pinned_source_json_and_the_archive_it_names_are_both_verified(
        self, monkeypatch
    ) -> None:
        registry = Registry(monkeypatch)
        result = BazelProvenance.check("rules_x", "1.0.0", SOURCE_PIN)
        assert result.outcome == "verified"
        # source.json against the lock's pin, then the archive against what source.json records,
        # each under the repository metadata.json names.
        assert registry.verified == [
            (SOURCE_PIN.removeprefix("sha256:"), ("github.com", "acme", "rules_x")),
            (ARCHIVE.hex(), ("github.com", "acme", "rules_x")),
        ]

    def test_a_pinned_archive_is_verified_on_its_own(self, monkeypatch) -> None:
        registry = Registry(monkeypatch)
        assert BazelProvenance.check("rules_x", "1.0.0", ARCHIVE_PIN).outcome == "verified"
        assert [digest for digest, _ in registry.verified] == [ARCHIVE.hex()]

    @pytest.mark.conformance("bazel", "UNI-17")
    def test_a_signature_that_does_not_cover_the_pin_is_invalid(self, monkeypatch) -> None:
        Registry(monkeypatch, verdict=attest.Outcome.INVALID)
        result = BazelProvenance.check("rules_x", "1.0.0", SOURCE_PIN)
        assert result.outcome == "invalid"
        assert "source.json" in result.detail

    @pytest.mark.conformance("bazel", "UNI-17")
    def test_a_bundle_swapped_after_bcr_recorded_it_is_invalid(self, monkeypatch) -> None:
        registry = Registry(monkeypatch, released=b'{"another": 1}\n')
        result = BazelProvenance.check("rules_x", "1.0.0", SOURCE_PIN)
        assert result.outcome == "invalid"
        assert "not the one BCR recorded" in result.detail
        assert not registry.verified

    @pytest.mark.conformance("bazel", "UNI-17")
    def test_a_bundle_from_a_repository_the_module_does_not_name_is_invalid(
        self, monkeypatch
    ) -> None:
        stranger = "https://github.com/mallory/rules_x/releases/download/v1.0.0"
        Registry(
            monkeypatch,
            attestations={
                "source.json": Registry.entry(f"{stranger}/source.json.intoto.jsonl"),
                "rules_x-v1.0.0.tar.gz": Registry.entry(
                    f"{stranger}/rules_x-v1.0.0.tar.gz.intoto.jsonl"
                ),
            },
        )
        result = BazelProvenance.check("rules_x", "1.0.0", SOURCE_PIN)
        assert result.outcome == "invalid"
        assert "mallory/rules_x" in result.detail

    def test_a_bundle_off_github_is_invalid(self, monkeypatch) -> None:
        Registry(
            monkeypatch,
            attestations={
                "rules_x-v1.0.0.tar.gz": Registry.entry("https://example.com/rules_x.intoto.jsonl")
            },
        )
        assert BazelProvenance.check("rules_x", "1.0.0", ARCHIVE_PIN).outcome == "invalid"

    def test_a_pin_the_registry_no_longer_serves_is_not_verified_against_other_files(
        self, monkeypatch
    ) -> None:
        registry = Registry(monkeypatch)
        result = BazelProvenance.check("rules_x", "1.0.0", "sha256:" + "0" * 64)
        assert result.outcome == "unverifiable"
        assert not registry.verified

    def test_no_pin_is_reported_as_such(self, monkeypatch) -> None:
        Registry(monkeypatch)
        assert BazelProvenance.check("rules_x", "1.0.0", None).outcome == "unpinned"

    def test_a_module_without_attestations_has_nothing_to_verify(self, monkeypatch) -> None:
        Registry(monkeypatch)
        assert BazelProvenance.check("rules_y", "2.0.0", SOURCE_PIN).outcome == "absent"

    def test_a_module_naming_no_github_repository_is_unverifiable(self, monkeypatch) -> None:
        Registry(monkeypatch, repository="https://gitlab.com/acme/rules_x")
        assert BazelProvenance.check("rules_x", "1.0.0", SOURCE_PIN).outcome == "unverifiable"

    def test_an_unreachable_registry_is_unverifiable(self, monkeypatch) -> None:
        def down(url):
            raise urllib.error.URLError("no route")

        monkeypatch.setattr(BazelProvenance, "_get", staticmethod(down))
        assert BazelProvenance.check("rules_x", "1.0.0", SOURCE_PIN).outcome == "unverifiable"
