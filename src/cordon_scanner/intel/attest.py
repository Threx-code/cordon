"""Cryptographic verification of a package's build provenance.

The registry client can already see *that* a release carries a sigstore
attestation (npm `--provenance`, PyPI PEP 740). This module answers the harder
question: is that attestation real, and was the artefact built by the source
repository the package claims? The gap between the two is exactly the attack
that matters -- a stolen publish token uploads a malicious build that still
names the honest repository, and only a signature check tied to a signing
identity tells the two apart.

**Why an extra, and why sigstore.** Verifying a bundle means checking a
Fulcio-issued certificate, a Rekor transparency-log inclusion proof, and a DSSE
signature over the artefact digest. That is a cryptographic stack the
zero-dependency base will not carry, and it is not a thing to reimplement: a
subtly wrong verifier in a security tool is worse than none, because it reports
confidence it has not earned. So the work is delegated to the `sigstore`
library, behind the `[attest]` extra. When the extra is absent the answer is
`UNVERIFIABLE`, never a crash and never a false pass.

**What is proved without downloading the artefact.** The lockfile already
records the artefact's own hash. That hash is what the attestation's subject
commits to, so passing it to `verify_artifact` proves the bundle attests to the
exact bytes this project pinned -- no second download, and a hash the registry
later swapped shows up as a verification failure rather than a quiet mismatch.

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

#: Digest algorithms this maps to sigstore's enum. npm provenance subjects a
#: sha512 of the tarball; PyPI records a sha256. Anything else is left
#: unverifiable rather than guessed at.
_ALGORITHMS = {"sha256": "SHA2_256", "sha512": "SHA2_512"}


class Outcome(enum.StrEnum):
    """The result of asking whether a bundle verifies."""

    VERIFIED = "verified"
    """The signature, the transparency-log entry, the artefact digest and the
    signing identity all checked out."""

    INVALID = "invalid"
    """The bundle was cryptographically rejected, or it was signed by an
    identity other than the declared repository. This is the actionable one."""

    UNVERIFIABLE = "unverifiable"
    """Verification could not be attempted: the `[attest]` extra is absent, the
    trust infrastructure was unreachable, the declared repository is missing or
    on an unsupported forge, or the bundle did not parse. Distinct from
    `INVALID`, because "not checked" and "checked and failed" are opposite
    facts -- the same distinction the registry client draws for reachability."""


@dataclass(frozen=True, slots=True)
class Result:
    outcome: Outcome
    detail: str


def available() -> bool:
    """Whether the `[attest]` extra is installed."""
    from importlib.util import find_spec

    try:
        return find_spec("sigstore") is not None
    except (ImportError, ValueError):  # pragma: no cover - find_spec internals
        return False


def verify(
    bundle_json: str | bytes,
    *,
    digest_hex: str,
    algorithm: str,
    source_repo: tuple[str, str, str] | None,
    offline: bool = False,
) -> Result:
    """Verify a sigstore bundle against a pinned digest and a declared repo.

    `digest_hex`/`algorithm` are the artefact hash the lockfile pinned.
    `source_repo` is the `(forge, owner, name)` the manifest declares, and the
    signing certificate must match it. Any reason the check cannot run returns
    `UNVERIFIABLE`; only a cryptographic or identity rejection returns
    `INVALID`.
    """
    if not available():
        return Result(Outcome.UNVERIFIABLE, "the [attest] extra is not installed")

    sig_algorithm = _ALGORITHMS.get(algorithm.lower())
    if sig_algorithm is None:
        return Result(Outcome.UNVERIFIABLE, f"unsupported digest algorithm {algorithm!r}")

    policy = _identity_policy(source_repo)
    if policy is None:
        forge = source_repo[0] if source_repo else "none"
        return Result(
            Outcome.UNVERIFIABLE,
            f"no supported source-repository identity to verify against (forge: {forge})",
        )

    from sigstore.errors import Error as SigstoreError
    from sigstore.hashes import HashAlgorithm, Hashed  # type: ignore[attr-defined]
    from sigstore.models import Bundle
    from sigstore.verify import Verifier
    from sigstore.verify.policy import VerificationError  # type: ignore[attr-defined]

    try:
        bundle = Bundle.from_json(bundle_json)
    except Exception as exc:
        return Result(
            Outcome.UNVERIFIABLE, f"the attestation bundle did not parse: {type(exc).__name__}"
        )

    try:
        hashed = Hashed(algorithm=HashAlgorithm[sig_algorithm], digest=bytes.fromhex(digest_hex))
    except ValueError:
        return Result(Outcome.UNVERIFIABLE, "the pinned digest is not valid hex")

    try:
        verifier = Verifier.production(offline=offline)
    except SigstoreError as exc:
        # The trust root could not be established (network, or a stale cache).
        # That is an inability to check, not a failed check.
        return Result(Outcome.UNVERIFIABLE, f"trust root unavailable: {type(exc).__name__}")

    try:
        verifier.verify_artifact(hashed, bundle, policy)
    except VerificationError as exc:
        return Result(Outcome.INVALID, f"verification failed: {exc}")
    except SigstoreError as exc:
        # A network or infrastructure error mid-verification is not a rejection.
        return Result(
            Outcome.UNVERIFIABLE, f"verification could not complete: {type(exc).__name__}"
        )

    owner, name = (source_repo[1], source_repo[2]) if source_repo else ("", "")
    return Result(
        Outcome.VERIFIED, f"built by github.com/{owner}/{name} and signed for that identity"
    )


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
        return _npm_bundles(payload)
    if ecosystem == "pypi":
        return _pypi_bundles(payload)
    return ()


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


def _pypi_bundles(payload: dict[str, Any]) -> tuple[str, ...]:
    try:
        from pypi_attestations import Provenance
    except ImportError:
        return ()
    try:
        provenance = Provenance.model_validate(payload)
    except Exception:
        return ()
    out: list[str] = []
    for bundle_group in provenance.attestation_bundles:
        for attestation in bundle_group.attestations:
            try:
                out.append(attestation.to_bundle().to_json())
            except Exception:  # noqa: S112 - an unconvertible attestation is one fewer to check, not an error
                continue
    return tuple(out)


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
        digest = _decode_hex_or_base64(rest, expected_bytes)
        return (algorithm, digest) if digest else None
    return None


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


def _identity_policy(source_repo: tuple[str, str, str] | None) -> Any:
    """A sigstore policy that pins the signer to the declared repository.

    Returns a sigstore `VerificationPolicy` (typed `Any`, because the type lives
    behind the extra) or `None` when no supported identity can be built.

    Only GitHub is mapped, because the certificate extensions this asserts are
    GitHub Actions' OIDC claims; a package declaring a repository on another
    forge is left unverifiable rather than checked against the wrong claim.
    """
    if source_repo is None:
        return None
    forge, owner, name = source_repo
    if forge != "github.com" or not owner or not name:
        return None

    from sigstore.verify import policy

    return policy.AllOf(
        [
            policy.OIDCIssuer(GITHUB_OIDC_ISSUER),
            policy.GitHubWorkflowRepository(f"{owner}/{name}"),
        ]
    )


__all__ = [
    "GITHUB_OIDC_ISSUER",
    "Outcome",
    "Result",
    "available",
    "extract_bundles",
    "parse_integrity",
    "verify",
]
