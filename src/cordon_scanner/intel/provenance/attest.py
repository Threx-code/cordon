"""Cryptographic verification of a package's build provenance.

The registry client can already see *that* a release carries a sigstore
attestation (npm `--provenance`, PyPI PEP 740). This module answers the harder
question: is that attestation real, and was the artefact built by the source
repository the package claims? The gap between the two is exactly the attack
that matters -- a stolen publish token uploads a malicious build that still
names the honest repository, and only a signature check tied to a signing
identity tells the two apart.

**Verified by the project's own code.** Verifying a bundle means checking a
Fulcio-issued certificate and its certificate-transparency timestamps, a Rekor
inclusion proof with its signed checkpoint and signed entry timestamp, and a DSSE
signature. A subtly wrong verifier in a security tool is worse than none, because
it reports confidence it has not earned -- and a third-party one is code that runs
with the scanner's privileges. So the stack is Cordon's own (`sigstore_bundle`),
held to evidence rather than trust: every Wycheproof vector for its signature
schemes, every real npm attestation in the measured corpus against sigstore-python,
and every one of them tampered fourteen ways, none of which verifies.

**What is proved without downloading the artefact.** The lockfile already
records the artefact's own hash, and that hash is what the attestation's subject
commits to -- so comparing the two proves the bundle attests to the exact bytes
this project pinned, with no second download, and a hash the registry later
swapped shows up as a rejection rather than a quiet mismatch.

Both halves are needed and neither is sufficient. `verify_dsse` establishes that
the envelope was signed by the identity the policy names, and says nothing about
which artefact the statement inside it describes; the subject comparison
establishes that the statement describes this artefact, and says nothing about
who signed it. `verify` performs both, in that order, and treats a signed
statement about some other release as `INVALID` rather than as proof.

**The identity tie-in.** A valid signature is not enough: it must be the
*right* signer. The policy requires the certificate's source-repository identity
to equal the repository the manifest declares, which is the same identity
`registry.repository_identity` resolves for the mismatch check. "What it claims"
and "what actually signed it" then close on each other.
"""

from __future__ import annotations

import base64
import binascii
import enum
import json
from dataclasses import dataclass
from typing import Any

#: OIDC issuer for GitHub Actions, the workload identity that signs a
#: `--provenance` publish. The identity policy is pinned to it so a certificate
#: for the right repository from a different issuer is not accepted.
GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"

#: Digest algorithms a pinned artefact hash may use. npm provenance subjects a
#: sha512 of the tarball; PyPI records a sha256. Anything else is left
#: unverifiable rather than guessed at.
_ALGORITHMS = {"sha256": "SHA2_256", "sha512": "SHA2_512"}

#: The DSSE payload type npm and PyPI provenance both carry. Asserted before the
#: payload is read, because `verify_dsse` performs no validation of either the
#: type or the payload and says so.
_IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"


class Outcome(enum.StrEnum):
    """The result of asking whether a bundle verifies."""

    VERIFIED = "verified"
    """The signature, the transparency-log entry, the artefact digest and the
    signing identity all checked out."""

    INVALID = "invalid"
    """The bundle was cryptographically rejected, or it was signed by an
    identity other than the declared repository. This is the actionable one."""

    UNVERIFIABLE = "unverifiable"
    """Verification could not be attempted: the declared repository is missing or
    on an unsupported forge, the bundle did not parse, or it uses evidence this
    verifier does not read. Distinct from
    `INVALID`, because "not checked" and "checked and failed" are opposite
    facts -- the same distinction the registry client draws for reachability."""


@dataclass(frozen=True, slots=True)
class Result:
    outcome: Outcome
    detail: str


class SigstoreVerification:
    """Verifying a sigstore bundle against a pinned digest and a declared repository.

    The cryptography is the project's own (`sigstore_bundle.BundleVerifier`, over `x509`,
    `transparency`, `_ecdsa`, `_rsa`, `_ed25519`), checked against the trust material Cordon pins
    (`intel/data/sigstore-trusted-root.json`, `intel/data/npm-registry-keys.json`). No
    third-party verifier runs, so there is no extra to be absent: `available` is always true.
    """

    #: Fulcio's certificate extensions naming the OIDC issuer: the current one (DER-encoded
    #: UTF8String) and the deprecated one (raw bytes), which older certificates carry alone.
    _ISSUER_V2 = "1.3.6.1.4.1.57264.1.8"
    _ISSUER_V1 = "1.3.6.1.4.1.57264.1.1"
    #: The GitHub workflow repository claim (`owner/name`, raw bytes).
    _REPOSITORY = "1.3.6.1.4.1.57264.1.5"

    @staticmethod
    def available() -> bool:
        """Always: verification is built in."""
        return True

    @staticmethod
    def verify(
        bundle_json: str | bytes,
        *,
        digest_hex: str,
        algorithm: str,
        source_repo: tuple[str, str, str] | None,
        offline: bool = False,
    ) -> Result:
        """Verify a sigstore bundle against a pinned digest and a declared repo.

        `digest_hex`/`algorithm` are the artefact hash the lockfile pinned. `source_repo` is
        the `(forge, owner, name)` the manifest declares, and the signing certificate must
        match it. Any reason the check cannot run returns `UNVERIFIABLE`; only a cryptographic,
        identity or subject rejection returns `INVALID`. `offline` is accepted for callers'
        sake: the trust material is pinned, so verification never goes to the network.
        """
        from cordon_scanner.intel.provenance.sigstore_bundle import (
            BundleError,
            BundleVerifier,
            Rejected,
        )

        del offline
        if algorithm.lower() not in _ALGORITHMS:
            return Result(Outcome.UNVERIFIABLE, f"unsupported digest algorithm {algorithm!r}")
        try:
            bytes.fromhex(digest_hex)
        except ValueError:
            return Result(Outcome.UNVERIFIABLE, "the pinned digest is not valid hex")
        repository = SigstoreVerification._repository(source_repo)
        if repository is None:
            forge = source_repo[0] if source_repo else "none"
            return Result(
                Outcome.UNVERIFIABLE,
                f"no supported source-repository identity to verify against (forge: {forge})",
            )

        try:
            verified = BundleVerifier().verify(
                bundle_json, digest_hex=digest_hex, algorithm=algorithm.lower()
            )
        except Rejected as exc:
            return Result(Outcome.INVALID, f"verification failed: {exc}")
        except BundleError as exc:
            return Result(Outcome.UNVERIFIABLE, f"the bundle could not be checked: {exc}")

        certificate = verified.certificate
        if certificate is None:
            # npm's registry signed it: proof the registry published these bytes, not of who
            # built them. Verified cryptographically, and still no answer to the identity question.
            return Result(
                Outcome.UNVERIFIABLE,
                "signed by the npm registry's key, which attests publication, not a source repository",
            )
        issuer = certificate.extension_text(
            SigstoreVerification._ISSUER_V2, der_string=True
        ) or certificate.extension_text(SigstoreVerification._ISSUER_V1, der_string=False)
        if issuer != GITHUB_OIDC_ISSUER:
            # Signed, but by an identity no source repository stands behind: a developer's email
            # through Google or Microsoft login, which is how many Maven Central artefacts are
            # signed. It is a question this check cannot answer, not a forgery.
            return Result(
                Outcome.UNVERIFIABLE,
                f"signed by an identity from {issuer}, which is not tied to a source repository",
            )
        signer = certificate.extension_text(SigstoreVerification._REPOSITORY, der_string=False)
        if signer is None:
            return Result(
                Outcome.INVALID,
                "verification failed: the certificate names no GitHub workflow repository",
            )
        # GitHub holds no two repositories whose names differ only in case, and a manifest's
        # spelling need not be the stored one (typedoc declares `TypeStrong/TypeDoc`; its
        # certificates say `TypeStrong/typedoc`).
        if signer.lower() != repository.lower():
            # Worded as the detector reads it (`ProvenanceDetector._renamed` retries a renamed
            # repository on exactly this refusal).
            return Result(
                Outcome.INVALID,
                f"verification failed: Certificate's GitHubWorkflowRepository does not match "
                f"(got '{signer}', expected '{repository}')",
            )

        subject = (
            SigstoreVerification._subject(
                verified.payload_type, verified.payload, digest_hex, algorithm.lower()
            )
            if verified.payload is not None
            else Result(Outcome.VERIFIED, "the signature covers the pinned digest")
        )
        if subject.outcome is not Outcome.VERIFIED:
            return subject
        return Result(
            Outcome.VERIFIED, f"built by github.com/{repository} and signed for that identity"
        )

    @staticmethod
    def _repository(source_repo: tuple[str, str, str] | None) -> str | None:
        """`owner/name` for a GitHub repository, or None: the certificate claims checked are
        GitHub Actions' OIDC claims, so another forge is left unverifiable rather than checked
        against the wrong claim."""
        if source_repo is None:
            return None
        forge, owner, name = source_repo
        if forge != "github.com" or not owner or not name:
            return None
        return f"{owner}/{name}"

    @staticmethod
    def _subject(
        payload_type: str | None, payload: bytes, digest_hex: str, algorithm: str
    ) -> Result:
        """Whether the signed in-toto statement is about the pinned artefact.

        Not optional: the envelope's signature proves who signed the statement and says nothing
        about which artefact it describes -- so stopping there would accept a genuine
        attestation for some other release of the same package as proof of this one.
        """
        if payload_type != _IN_TOTO_PAYLOAD_TYPE:
            return Result(
                Outcome.UNVERIFIABLE,
                f"the envelope carries an unknown payload type {payload_type!r}",
            )
        try:
            statement = json.loads(payload)
        except (json.JSONDecodeError, ValueError):
            return Result(Outcome.UNVERIFIABLE, "the in-toto statement did not parse")
        subjects = statement.get("subject") if isinstance(statement, dict) else None
        if not isinstance(subjects, list) or not subjects:
            return Result(Outcome.UNVERIFIABLE, "the in-toto statement names no subject")
        comparable = False
        for subject in subjects:
            digests = subject.get("digest") if isinstance(subject, dict) else None
            recorded = digests.get(algorithm) if isinstance(digests, dict) else None
            if not isinstance(recorded, str):
                continue
            comparable = True
            if recorded.strip().lower() == digest_hex.lower():
                return Result(Outcome.VERIFIED, "the statement covers the pinned digest")
        if not comparable:
            return Result(
                Outcome.UNVERIFIABLE,
                f"the statement records no {algorithm} digest to compare the pin against",
            )
        return Result(
            Outcome.INVALID,
            f"the attestation is signed but its subject is not the pinned {algorithm} digest",
        )


class AttestationDocuments:
    """Sigstore bundles and integrity digests out of registry documents."""

    @staticmethod
    def extract_bundles(ecosystem: str, payload: dict[str, Any] | None) -> tuple[str, ...]:
        """The sigstore bundles inside a registry's raw attestation document.

        npm serves sigstore bundles almost directly; PyPI serves PEP 740 provenance,
        which `pypi-attestations` converts into the same bundle shape. Either way the
        output is bundle JSON that `verify` consumes. Anything that does not convert
        is dropped rather than raised: a bundle that cannot even be read is not a
        verification failure, it is one fewer bundle to check, and the caller reports
        the difference between "none verified" and "one failed".
        """
        if not payload:
            return ()
        if ecosystem == "npm":
            return AttestationDocuments._npm_bundles(payload)
        if ecosystem == "pypi":
            return AttestationDocuments._pypi_bundles(payload)
        if ecosystem in ("maven", "gradle"):
            bundle = payload.get("bundle")
            return (json.dumps(bundle),) if isinstance(bundle, dict) and bundle else ()
        if ecosystem in ("rubygems", "image"):
            # RubyGems.org's attestations; an image's referrers, one bundle each.
            bundles = payload.get("bundles")
            return (
                tuple(json.dumps(b) for b in bundles if isinstance(b, dict))
                if isinstance(bundles, list)
                else ()
            )
        return ()

    @staticmethod
    def _npm_bundles(payload: dict[str, Any]) -> tuple[str, ...]:
        out: list[str] = []
        attestations = payload.get("attestations")
        if not isinstance(attestations, list):
            return ()
        for attestation in attestations:
            bundle = attestation.get("bundle") if isinstance(attestation, dict) else None
            if isinstance(bundle, dict):
                out.append(json.dumps(bundle))
        return tuple(out)

    @staticmethod
    def _pypi_bundles(payload: dict[str, Any]) -> tuple[str, ...]:
        """PEP 740 provenance as sigstore bundles: each attestation's certificate, log entries
        and DSSE envelope (its statement and signature), in bundle form (version 0.3)."""
        out: list[str] = []
        groups = payload.get("attestation_bundles") if isinstance(payload, dict) else None
        for group in groups if isinstance(groups, list) else []:
            attestations = group.get("attestations") if isinstance(group, dict) else None
            for attestation in attestations if isinstance(attestations, list) else []:
                bundle = AttestationDocuments._pep740_bundle(attestation)
                if bundle is not None:
                    out.append(json.dumps(bundle))
        return tuple(out)

    @staticmethod
    def _pep740_bundle(attestation: Any) -> dict[str, Any] | None:
        if not isinstance(attestation, dict) or attestation.get("version") != 1:
            return None
        material = attestation.get("verification_material")
        envelope = attestation.get("envelope")
        if not isinstance(material, dict) or not isinstance(envelope, dict):
            return None
        certificate, entries = material.get("certificate"), material.get("transparency_entries")
        statement, signature = envelope.get("statement"), envelope.get("signature")
        if not all(
            isinstance(v, str) for v in (certificate, statement, signature)
        ) or not isinstance(entries, list):
            return None
        return {
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {
                "certificate": {"rawBytes": certificate},
                "tlogEntries": entries,
            },
            "dsseEnvelope": {
                "payload": statement,
                "payloadType": _IN_TOTO_PAYLOAD_TYPE,
                "signatures": [{"sig": signature}],
            },
        }

    @staticmethod
    def parse_integrity(integrity: str | None) -> tuple[str, str] | None:
        """A lockfile integrity string as `(algorithm, hex-digest)`, or `None`.

        Lockfiles record the artefact hash in a few shapes: Subresource Integrity
        (`sha512-<base64>`, npm), a prefixed hex (`sha256:<hex>`, pip), or bare hex.
        This is the digest the attestation must commit to, so parsing it wrong is a
        verification that checks the wrong bytes -- hence the strict return of
        `None` for anything that does not cleanly resolve to a known algorithm and a
        hash of the right length.
        """
        if not integrity:
            return None
        text = integrity.strip()
        for separator in ("-", ":"):
            prefix, sep, rest = text.partition(separator)
            if not sep:
                continue
            algorithm = prefix.lower()
            if algorithm not in _ALGORITHMS or not rest:
                continue
            expected_bytes = {"sha256": 32, "sha512": 64}[algorithm]
            digest = AttestationDocuments._decode_hex_or_base64(rest, expected_bytes)
            return (algorithm, digest) if digest else None
        return None

    @staticmethod
    def _decode_hex_or_base64(value: str, expected_bytes: int) -> str | None:
        """`value` as a hex digest of `expected_bytes`, from hex or base64 input."""
        try:
            raw = bytes.fromhex(value)
        except ValueError:
            try:
                raw = base64.b64decode(value, validate=True)
            except (binascii.Error, ValueError):
                return None
        return raw.hex() if len(raw) == expected_bytes else None


__all__ = [
    "GITHUB_OIDC_ISSUER",
    "AttestationDocuments",
    "Outcome",
    "Result",
    "SigstoreVerification",
]
