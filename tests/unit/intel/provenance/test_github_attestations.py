"""A GitHub Action's release attestation (`intel/provenance/github_attestations`, `cms`), verified against GitHub's own trusted root.

The bundle is the real one GitHub serves for sigstore/cosign-installer v4.1.4 (`github/attestations.json`, fetched from
api.github.com on 2026-11-25), and the root is the real pinned file, so the certificate chain, the RFC 3161 time-stamp and the DSSE
signature are the real ones. What is tested is each way they fail, and what each failure is called."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import urllib.error
from typing import Any

import pytest

from cordon_scanner.intel.provenance.releases.cms import Authority, CmsError, TimestampToken
from cordon_scanner.intel.provenance.releases.github_attestations import (
    GitHubAttestations,
    GitHubRoot,
    Release,
)
from cordon_scanner.intel.provenance.sigstore_bundle import TrustRoot
from support import ROOT

DATA = ROOT / "tests" / "unit" / "intel" / "provenance" / "github"
REPOSITORY, TAG = "sigstore/cosign-installer", "v4.1.4"
COMMIT = "881c63bd87e38389154debd8331404ce7ca8a3ab"
RELEASE = Release(REPOSITORY, TAG, COMMIT)


class Real:
    """The recorded bundle, copied for each test so one can break it."""

    @staticmethod
    def bundle() -> dict[str, Any]:
        listed = json.loads((DATA / "attestations.json").read_text(encoding="utf-8"))
        return copy.deepcopy(listed["attestations"][0]["bundle"])

    @staticmethod
    def signature(bundle: dict[str, Any]) -> bytes:
        return base64.b64decode(bundle["dsseEnvelope"]["signatures"][0]["sig"])

    @staticmethod
    def timestamp(bundle: dict[str, Any]) -> bytes:
        return base64.b64decode(
            bundle["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"][0][
                "signedTimestamp"
            ]
        )


class TestThePinnedRoot:
    def test_the_file_is_the_one_github_published(self) -> None:
        raw = (TrustRoot.DATA / "github-trusted-root.json").read_bytes()
        # Fetched twice from GitHub's TUF repository on 2026-11-25; the same digest its TUF targets record.
        assert (
            hashlib.sha256(raw).hexdigest()
            == "484cdfe1a7c65479c5ba2a22193d1be90f0020db1997de696ab207434c62fbb7"
        )

    def test_it_holds_six_certificate_authorities_and_six_time_stamping_ones_and_no_log(
        self,
    ) -> None:
        root = GitHubRoot.production()
        assert len(root.certificate_authorities) == 6 and len(root.timestamp_authorities) == 6
        assert "tlogs" not in json.loads(
            (TrustRoot.DATA / "github-trusted-root.json").read_text(encoding="utf-8")
        )


class TestTheRealRelease:
    def test_the_attestation_of_the_release_verifies(self) -> None:
        found = GitHubAttestations.verify(Real.bundle(), RELEASE)
        assert found.outcome == "verified" and COMMIT in found.detail

    def test_a_release_given_by_commit_alone_verifies(self) -> None:
        assert (
            GitHubAttestations.verify(Real.bundle(), Release(REPOSITORY, "", COMMIT)).outcome
            == "verified"
        )

    @pytest.mark.parametrize(
        ("release", "text"),
        [
            (Release("sigstore/cosign", TAG, COMMIT), "another repository"),
            (Release(REPOSITORY, "v4.1.5", COMMIT), "another tag"),
            (Release(REPOSITORY, TAG, "0" * 40), "another commit"),
        ],
    )
    def test_an_attestation_of_another_release_is_not_this_one(
        self, release: Release, text: str
    ) -> None:
        found = GitHubAttestations.verify(Real.bundle(), release)
        assert found.outcome == "invalid" and text in found.detail

    def test_the_stamp_is_the_time_github_signed_it(self) -> None:
        bundle = Real.bundle()
        stamp = TimestampToken.verify(
            Real.timestamp(bundle),
            Real.signature(bundle),
            GitHubRoot.production().timestamp_authorities,
        )
        assert (stamp.time.year, stamp.time.month, stamp.time.day, stamp.time.hour) == (
            2026,
            11,
            24,
            16,
        ) and stamp.hash_algorithm == "sha256"


class TestWhatCannotBeTrusted:
    @staticmethod
    def check(bundle: dict[str, Any]) -> Any:
        return GitHubAttestations.verify(bundle, RELEASE)

    def test_a_statement_changed_after_it_was_signed_fails_the_signature(self) -> None:
        bundle = Real.bundle()
        payload = base64.b64decode(bundle["dsseEnvelope"]["payload"]).replace(
            b"cosign-installer", b"cosign-installed"
        )
        bundle["dsseEnvelope"]["payload"] = base64.b64encode(payload).decode()
        found = self.check(bundle)
        assert found.outcome == "invalid"

    def test_a_signature_that_is_not_the_one_stamped_fails_the_stamp(self) -> None:
        bundle = Real.bundle()
        raw = bytearray(Real.signature(bundle))
        raw[-1] ^= 1
        bundle["dsseEnvelope"]["signatures"][0]["sig"] = base64.b64encode(bytes(raw)).decode()
        found = self.check(bundle)
        assert found.outcome == "invalid" and "stamp is over other data" in found.detail

    def test_a_stamp_with_a_changed_byte_is_refused(self) -> None:
        bundle = Real.bundle()
        raw = bytearray(Real.timestamp(bundle))
        raw[len(raw) // 2] ^= 1
        bundle["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"][0][
            "signedTimestamp"
        ] = base64.b64encode(bytes(raw)).decode()
        assert self.check(bundle).outcome == "invalid"

    def test_a_stamp_signed_by_nobody_pinned_is_refused(self) -> None:
        bundle = Real.bundle()
        with pytest.raises(CmsError, match="pinned time-stamping authority"):
            TimestampToken.verify(Real.timestamp(bundle), Real.signature(bundle), [])

    def test_a_stamp_outside_every_authoritys_window_is_refused(self) -> None:
        bundle = Real.bundle()
        authorities = [
            Authority(a.chain, a.start, a.start)
            for a in GitHubRoot.production().timestamp_authorities
        ]
        with pytest.raises(CmsError, match="pinned time-stamping authority"):
            TimestampToken.verify(Real.timestamp(bundle), Real.signature(bundle), authorities)

    def test_a_certificate_authority_that_is_not_pinned_is_refused(self) -> None:
        root = GitHubRoot.production()
        root.certificate_authorities, kept = [], root.certificate_authorities
        try:
            found = GitHubAttestations.verify(Real.bundle(), RELEASE, root)
        finally:
            root.certificate_authorities = kept
        assert found.outcome == "invalid" and "pinned GitHub certificate authority" in found.detail

    def test_a_certificate_that_is_not_githubs_release_signer_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(GitHubAttestations, "SIGNER", "https://dotcom.example.invalid")
        found = self.check(Real.bundle())
        assert found.outcome == "invalid" and "release signer" in found.detail

    def test_two_stamps_or_none_are_refused(self) -> None:
        bundle = Real.bundle()
        stamps = bundle["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"]
        stamps.append(copy.deepcopy(stamps[0]))
        assert self.check(bundle).outcome == "invalid"
        stamps.clear()
        assert self.check(bundle).outcome == "invalid"

    @pytest.mark.parametrize(
        "media", ["application/vnd.dev.sigstore.bundle+json;version=0.1", "", "text/plain"]
    )
    def test_a_bundle_of_a_kind_not_read_is_refused(self, media: str) -> None:
        bundle = Real.bundle()
        bundle["mediaType"] = media
        assert self.check(bundle).outcome == "invalid"

    def test_an_envelope_of_another_kind_is_refused(self) -> None:
        bundle = Real.bundle()
        bundle["dsseEnvelope"]["payloadType"] = "text/plain"
        assert self.check(bundle).outcome == "invalid"

    @pytest.mark.parametrize("junk", [None, "x", [], {}, 3])
    def test_something_that_is_not_a_bundle_is_refused(self, junk: Any) -> None:
        assert GitHubAttestations.verify(junk, RELEASE).outcome == "invalid"

    def test_an_attestation_that_is_not_a_release_statement_is_refused(self) -> None:
        bundle = Real.bundle()
        statement = json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"]))
        statement["predicateType"] = "https://slsa.dev/provenance/v1"
        # Re-signing is impossible, so the signature fails first: the statement check is what the helper reaches directly.
        with pytest.raises(Exception, match="not a release attestation"):
            GitHubAttestations._statement(statement, RELEASE)


class TestAskingGitHub:
    def serve(self, monkeypatch: pytest.MonkeyPatch, answers: dict[str, Any]) -> list[str]:
        asked: list[str] = []

        def get(path: str) -> Any:
            asked.append(path)
            if isinstance(answers.get(path), Exception):
                raise answers[path]
            return answers.get(path)

        monkeypatch.setattr(GitHubAttestations, "get", staticmethod(get))
        return asked

    def listed(self) -> dict[str, Any]:
        return json.loads((DATA / "attestations.json").read_text(encoding="utf-8"))

    def test_a_tag_is_resolved_to_its_commit_and_the_attestation_asked_for_that_commit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asked = self.serve(
            monkeypatch,
            {
                f"/repos/{REPOSITORY}/git/ref/tags/{TAG}": {
                    "object": {"type": "commit", "sha": COMMIT}
                },
                f"/repos/{REPOSITORY}/attestations/sha1:{COMMIT}": self.listed(),
            },
        )
        assert GitHubAttestations.check(REPOSITORY, TAG, None).outcome == "verified"
        assert asked == [
            f"/repos/{REPOSITORY}/git/ref/tags/{TAG}",
            f"/repos/{REPOSITORY}/attestations/sha1:{COMMIT}",
        ]

    def test_an_annotated_tag_is_followed_to_the_commit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self.serve(
            monkeypatch,
            {
                f"/repos/{REPOSITORY}/git/ref/tags/{TAG}": {
                    "object": {"type": "tag", "sha": "a" * 40}
                },
                f"/repos/{REPOSITORY}/git/tags/{'a' * 40}": {
                    "object": {"type": "commit", "sha": COMMIT}
                },
                f"/repos/{REPOSITORY}/attestations/sha1:{COMMIT}": self.listed(),
            },
        )
        assert GitHubAttestations.check(REPOSITORY, TAG, None).outcome == "verified"

    def test_a_commit_pin_is_asked_directly_and_a_path_inside_the_repository_is_the_repositorys(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asked = self.serve(
            monkeypatch, {f"/repos/{REPOSITORY}/attestations/sha1:{COMMIT}": self.listed()}
        )
        assert (
            GitHubAttestations.check(f"{REPOSITORY}/sub/dir", COMMIT.upper(), None).outcome
            == "verified"
        )
        assert asked == [f"/repos/{REPOSITORY}/attestations/sha1:{COMMIT}"]

    def test_a_repository_that_publishes_no_attestation_is_absent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self.serve(
            monkeypatch,
            {
                f"/repos/{REPOSITORY}/git/ref/tags/{TAG}": {
                    "object": {"type": "commit", "sha": COMMIT}
                },
                f"/repos/{REPOSITORY}/attestations/sha1:{COMMIT}": {"attestations": []},
            },
        )
        assert GitHubAttestations.check(REPOSITORY, TAG, None).outcome == "absent"

    def test_a_tag_the_repository_does_not_have_is_absent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self.serve(monkeypatch, {})
        assert GitHubAttestations.check(REPOSITORY, "v0", None).outcome == "absent"

    def test_an_attestation_listed_for_the_commit_that_is_not_this_release_is_invalid(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self.serve(
            monkeypatch,
            {
                f"/repos/{REPOSITORY}/git/ref/tags/v9": {
                    "object": {"type": "commit", "sha": COMMIT}
                },
                f"/repos/{REPOSITORY}/attestations/sha1:{COMMIT}": self.listed(),
            },
        )
        assert GitHubAttestations.check(REPOSITORY, "v9", None).outcome == "invalid"

    def test_a_github_that_cannot_be_asked_is_unverifiable_not_invalid(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self.serve(
            monkeypatch,
            {f"/repos/{REPOSITORY}/git/ref/tags/{TAG}": urllib.error.URLError("unreachable")},
        )
        assert GitHubAttestations.check(REPOSITORY, TAG, None).outcome == "unverifiable"

    @pytest.mark.parametrize(
        ("name", "version"), [("actions", "v1"), ("", "v1"), ("actions/checkout", "")]
    )
    def test_a_name_or_version_that_is_no_release_is_absent(self, name: str, version: str) -> None:
        assert GitHubAttestations.check(name, version, None).outcome == "absent"

    def test_the_operators_token_goes_to_github_only_as_a_bearer_header(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: list[Any] = []

        class Opener:
            def open(self, request: Any, timeout: float = 0) -> Any:
                seen.append((request.full_url, request.get_header("Authorization")))
                raise urllib.error.HTTPError(request.full_url, 404, "x", {}, None)  # type: ignore[arg-type]

        monkeypatch.setenv("CORDON_GITHUB_TOKEN", "t0ken")
        monkeypatch.setattr("urllib.request.build_opener", lambda *a: Opener())
        assert GitHubAttestations.get("/repos/a/b") is None
        assert seen == [("https://api.github.com/repos/a/b", "Bearer t0ken")]
