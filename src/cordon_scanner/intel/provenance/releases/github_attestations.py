"""A GitHub Action's release attestation, verified against GitHub's own Sigstore trust root.

A repository that publishes releases as *immutable* has GitHub sign an attestation of each: an in-toto statement
(`https://in-toto.io/attestation/release/v0.2`) that the release of `<owner>/<repo>` at a tag is the commit it names:

    GET https://api.github.com/repos/<owner>/<repo>/attestations/sha1:<commit>
        attestations[].bundle: a Sigstore bundle (v0.3): a DSSE envelope, the certificate GitHub's own Fulcio issued
        (subject alternative name `https://dotcom.releases.github.com`), and an RFC 3161 time-stamp of the signature

GitHub runs its own certificate and time-stamping authorities, published in a trusted root (`intel/data/github-trusted-root.json`,
fetched from GitHub's TUF repository: two fetches that agreed, the SHA-256 of the file matching the one its TUF targets record).
Checked from first principles, each link, against that root and no key the bundle carries:

1. the certificate chains to a pinned GitHub certificate authority valid at the time-stamp, is a leaf for code signing, and names
   GitHub's release signer;
2. the time-stamp is over the envelope's signature and is signed by a pinned GitHub time-stamping authority (`cms`), and the
   certificate was valid at the time it states: GitHub's certificates are short-lived and there is no transparency log to date a
   signature otherwise;
3. the DSSE signature verifies under the certificate's key;
4. the statement is the release of THIS repository at THIS tag, of THIS commit.

The answer is `verified`, `invalid` (a link failed: the attestation is not for this release, or is forged), `absent` (the repository
publishes no attestation for the commit) or `unverifiable` (GitHub could not be asked)."""

from __future__ import annotations

import datetime as dt
import http.client
import itertools
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, ClassVar, Final

from cordon_scanner.foundation.network.downloads import Download
from cordon_scanner.foundation.network.failures import NetworkFailure
from cordon_scanner.foundation.network.redirects import NoRedirects
from cordon_scanner.intel.provenance.bazel_provenance import ModuleCheck
from cordon_scanner.intel.provenance.releases.cms import Authority, CmsError, TimestampToken
from cordon_scanner.intel.provenance.sigstore_bundle import (
    BundleError,
    BundleVerifier,
    Strict,
    TrustRoot,
)
from cordon_scanner.intel.provenance.x509 import Certificate

API: Final = "https://api.github.com"
TIMEOUT: Final = 20.0
MAX_BYTES: Final = 4 << 20
HEX: Final = frozenset("0123456789abcdef")


class GitHubRoot:
    """GitHub's trusted root, as pinned in the package."""

    _loaded: ClassVar[GitHubRoot | None] = None
    MEDIA_TYPE: ClassVar[str] = "application/vnd.dev.sigstore.trustedroot+json;version=0.1"

    def __init__(self, document: dict[str, Any]) -> None:
        if document.get("mediaType") != self.MEDIA_TYPE:
            raise BundleError("a trusted root of an unknown media type")
        self.certificate_authorities = self._authorities(document, "certificateAuthorities")
        self.timestamp_authorities = self._authorities(document, "timestampAuthorities")

    @staticmethod
    def _authorities(document: dict[str, Any], key: str) -> list[Authority]:
        out = []
        for entry in document.get(key, []):
            chain = tuple(
                Certificate.from_der(Strict.b64(c["rawBytes"]))
                for c in entry["certChain"]["certificates"]
            )
            valid = entry.get("validFor") or {}
            out.append(
                Authority(chain, Strict.time(valid.get("start")), Strict.time(valid.get("end")))
            )
        return out

    @classmethod
    def production(cls) -> GitHubRoot:
        if cls._loaded is None:
            text = (TrustRoot.DATA / "github-trusted-root.json").read_text(encoding="utf-8")
            cls._loaded = cls(Strict.loads(text))
        return cls._loaded


class Release:
    """What a verified attestation must say: the release of `repository` at `tag` is `commit`."""

    def __init__(self, repository: str, tag: str, commit: str) -> None:
        self.repository, self.tag, self.commit = repository.lower(), tag, commit.lower()


class GitHubAttestations:
    SIGNER: ClassVar[str] = "https://dotcom.releases.github.com"
    PREDICATE: ClassVar[str] = "https://in-toto.io/attestation/release/v0.2"
    STATEMENT: ClassVar[str] = "https://in-toto.io/Statement/v1"
    PAYLOAD_TYPE: ClassVar[str] = "application/vnd.in-toto+json"
    BUNDLES: ClassVar[frozenset[str]] = frozenset({"application/vnd.dev.sigstore.bundle.v0.3+json"})

    # -- the cryptographic and statement checks (no network) -----------------------------------------------

    @classmethod
    def verify(cls, bundle: Any, release: Release, root: GitHubRoot | None = None) -> ModuleCheck:
        """One bundle against the pinned root and the release it must attest."""
        root = root or GitHubRoot.production()
        try:
            cls._verify(bundle, release, root)
        except (BundleError, CmsError, ValueError, KeyError, TypeError) as exc:
            return ModuleCheck("invalid", f"the release attestation did not verify: {exc}")
        return ModuleCheck(
            "verified", f"{release.repository}@{release.tag} is attested as commit {release.commit}"
        )

    @classmethod
    def _verify(cls, bundle: Any, release: Release, root: GitHubRoot) -> None:
        if not isinstance(bundle, dict) or bundle.get("mediaType") not in cls.BUNDLES:
            raise BundleError("a bundle of a kind not read")
        material = Strict.field(bundle, "verificationMaterial", dict)
        leaf = Certificate.from_der(
            Strict.b64(Strict.field(Strict.field(material, "certificate", dict), "rawBytes", str))
        )
        stamps = Strict.field(
            Strict.field(material, "timestampVerificationData", dict), "rfc3161Timestamps", list
        )
        if len(stamps) != 1:
            raise BundleError(
                "other than one time-stamp: GitHub's attestations carry one and have no transparency log"
            )
        envelope = Strict.field(bundle, "dsseEnvelope", dict)
        payload_type, payload, signature = BundleVerifier._envelope(envelope)
        if payload_type != cls.PAYLOAD_TYPE:
            raise BundleError("an envelope that is not an in-toto statement")
        stamp = TimestampToken.verify(
            Strict.b64(Strict.field(stamps[0], "signedTimestamp", str)),
            signature,
            root.timestamp_authorities,
        )
        cls._certificate(leaf, stamp.time, root)
        key = leaf.public_key()
        if not key.verify(
            BundleVerifier.pae(payload_type, payload), signature, BundleVerifier._hash_for(key)
        ):
            raise BundleError("the signature does not verify under the certificate's key")
        cls._statement(Strict.loads(payload), release)

    @classmethod
    def _certificate(cls, leaf: Certificate, when: dt.datetime, root: GitHubRoot) -> None:
        for authority in root.certificate_authorities:
            if not authority.holds(when):
                continue
            chain = authority.chain
            issuer = next((c for c in chain if c.subject == leaf.issuer), None)
            if issuer is None or not leaf.signed_by(issuer.public_key()):
                continue
            below = chain[chain.index(issuer) :]
            for child, parent in itertools.pairwise(below):
                if (
                    child.issuer != parent.subject
                    or not child.signed_by(parent.public_key())
                    or not parent.is_ca()
                ):
                    raise BundleError("the pinned certificate chain does not hold")
            top = below[-1]
            if top.subject != top.issuer or not top.signed_by(top.public_key()):
                raise BundleError("the pinned root is not self-signed")
            if not issuer.is_ca() or not all(c.valid_at(when) for c in below):
                raise BundleError(
                    "the issuing certificate is not a valid authority at the time-stamp"
                )
            if leaf.is_ca() or not leaf.valid_at(when):
                raise BundleError(
                    "the signing certificate is a CA, or was not valid at the time-stamp"
                )
            if Certificate.CODE_SIGNING not in leaf.extended_key_usages():
                raise BundleError("the signing certificate is not for code signing")
            if ("uri", cls.SIGNER) not in leaf.subject_alternative_names():
                raise BundleError("the signing certificate is not GitHub's release signer")
            return
        raise BundleError(
            "the signing certificate was not issued by a pinned GitHub certificate authority"
        )

    @classmethod
    def _statement(cls, statement: Any, release: Release) -> None:
        if not isinstance(statement, dict) or statement.get("_type") != cls.STATEMENT:
            raise BundleError("not an in-toto v1 statement")
        if statement.get("predicateType") != cls.PREDICATE:
            raise BundleError("a statement that is not a release attestation")
        subjects = Strict.field(statement, "subject", list)
        digests = [Strict.field(s, "digest", dict).get("sha1") for s in subjects]
        if digests != [release.commit]:
            raise BundleError("the statement attests another commit than the one asked")
        predicate = Strict.field(statement, "predicate", dict)
        if str(predicate.get("repository", "")).lower() != release.repository:
            raise BundleError("the statement attests another repository")
        if release.tag and predicate.get("tag") != release.tag:
            raise BundleError("the statement attests another tag")

    # -- asking GitHub ---------------------------------------------------------------------------------------

    @staticmethod
    def get(path: str) -> Any:
        """The JSON GitHub answers for `path`, None for a 404; the operator's `CORDON_GITHUB_TOKEN` goes to api.github.com only."""
        headers = {
            "User-Agent": "cordon-scanner",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        token = os.environ.get("CORDON_GITHUB_TOKEN", "").strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(f"{API}{path}", headers=headers)  # noqa: S310 - https, fixed host
        try:
            with urllib.request.build_opener(NoRedirects).open(
                request, timeout=TIMEOUT
            ) as response:
                body: bytes = Download.read(response, MAX_BYTES + 1)
        except urllib.error.HTTPError as exc:
            NetworkFailure.release(exc)
            if exc.code == 404:
                return None
            raise
        if len(body) > MAX_BYTES:
            raise ValueError("response too large")
        return json.loads(body)

    @classmethod
    def commit_of(cls, repository: str, ref: str) -> str | None:
        """The commit a tag (or a commit written out) names."""
        if len(ref) == 40 and set(ref.lower()) <= HEX:
            return ref.lower()
        found = cls.get(f"/repos/{repository}/git/ref/tags/{urllib.parse.quote(ref, safe='')}")
        target = found.get("object") if isinstance(found, dict) else None
        if not isinstance(target, dict):
            return None
        if (
            target.get("type") == "tag"
        ):  # an annotated tag points at a tag object, which points at the commit
            tag = cls.get(f"/repos/{repository}/git/tags/{target.get('sha')}")
            target = tag.get("object") if isinstance(tag, dict) else None
        sha = (
            str(target.get("sha"))
            if isinstance(target, dict) and target.get("type") == "commit"
            else ""
        )
        return sha.lower() if len(sha) == 40 and set(sha.lower()) <= HEX else None

    @classmethod
    def check(cls, name: str, version: str, integrity: str | None) -> ModuleCheck:
        """The release attestation of an Action at a tag (or commit): `name` is `owner/repo` (a path inside it is the repository's)."""
        parts = name.split("/")
        if len(parts) < 2 or not version:
            return ModuleCheck("absent", f"{name} names no repository release")
        repository = "/".join(parts[:2])
        try:
            commit = cls.commit_of(repository, version)
            if commit is None:
                return ModuleCheck("absent", f"{repository} has no tag {version}")
            listed = cls.get(f"/repos/{repository}/attestations/sha1:{commit}")
            bundles = [
                a.get("bundle")
                for a in (listed or {}).get("attestations", [])
                if isinstance(a, dict)
            ]
            if not bundles:
                return ModuleCheck(
                    "absent", f"{repository} publishes no release attestation for {commit}"
                )
            is_commit = version.lower() == commit
            release = Release(repository, "" if is_commit else version, commit)
            results = [cls.verify(b, release) for b in bundles]
            return next((r for r in results if r.outcome == "verified"), results[0])
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
            return ModuleCheck(
                "unverifiable", f"GitHub could not be asked: {NetworkFailure.reason(exc)}"
            )
