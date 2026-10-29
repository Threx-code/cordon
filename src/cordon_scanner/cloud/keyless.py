"""Keyless signing of a DSSE envelope, as Sigstore defines it, with the project's own code.

In a CI job the scan's results are signed for the job's identity, not for a key anyone keeps:

1. The CI provider issues an OIDC token for the audience `sigstore` -- the job's identity
   (repository, workflow, commit), never a person's (`results.CiSigningIdentity`).
2. A one-use P-256 key (`_p256`) signs the token's subject, proving possession, and Fulcio
   returns a certificate binding the key to that identity for ten minutes.
3. The key signs the envelope's pre-authentication encoding, and is dropped.
4. Rekor logs the signature with the certificate; its reply is the inclusion proof and the
   signed entry timestamp.
5. The pieces become a Sigstore bundle (version 0.3), and the bundle is verified -- by the same
   verifier that checks other people's attestations (`intel/provenance/sigstore_bundle`) --
   before it is returned. A bundle that does not verify is never sent.

Only the public Sigstore instance's fixed hosts are contacted, and the CI provider's token
endpoint the CI itself names.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.parse
import urllib.request
from typing import Any, ClassVar

from cordon_scanner.cloud._p256 import P256Signer
from cordon_scanner.cloud.ci_agent_token import CiAgentToken
from cordon_scanner.foundation.network.downloads import Download

MAX_TOKEN_REPLY_BYTES = 1 << 20
"""The most a token or signing endpoint's reply is read to: a JSON document of a few kilobytes,
read whole before, with no cap at all."""


class KeylessError(RuntimeError):
    """Signing could not complete: the envelope stays unsigned."""


class OidcToken:
    """The CI job's identity token for the audience `sigstore`, or None outside a CI that gives one."""

    AUDIENCE: ClassVar[str] = "sigstore"

    @staticmethod
    def detect() -> str | None:
        explicit = os.environ.get("SIGSTORE_ID_TOKEN")
        if explicit:
            return explicit.strip()
        url, bearer = (
            os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL"),
            os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
        )
        if url and bearer:
            return OidcToken._github(url, bearer)
        # The CI's own tool, asked for a token with Sigstore's audience (GitLab sets
        # SIGSTORE_ID_TOKEN itself, from the job's `id_tokens`).
        if os.environ.get("BUILDKITE") == "true":
            return CiAgentToken.request(
                ["buildkite-agent", "oidc", "request-token", "--audience", "sigstore"]
            )
        if os.environ.get("CIRCLECI") == "true":
            return CiAgentToken.request(
                ["circleci", "run", "oidc", "get", "--claims", '{"aud": "sigstore"}']
            )
        return None

    @staticmethod
    def _github(url: str, bearer: str) -> str | None:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https":
            return None
        query = urllib.parse.urlencode(
            [*urllib.parse.parse_qsl(parts.query), ("audience", OidcToken.AUDIENCE)]
        )
        request = urllib.request.Request(  # noqa: S310 - https only, checked above
            urllib.parse.urlunsplit(parts._replace(query=query)),
            headers={"Authorization": f"bearer {bearer}", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
                value = json.loads(Download.read(response, MAX_TOKEN_REPLY_BYTES)).get("value")
        except (OSError, ValueError):
            return None
        return value if isinstance(value, str) and value else None

    @staticmethod
    def subject(token: str) -> str:
        """The token's `sub` claim, which the proof of possession signs (Fulcio checks it)."""
        try:
            payload = token.split(".")[1]
            claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        except (IndexError, ValueError) as exc:
            raise KeylessError("the identity token is not a JWT") from exc
        sub = claims.get("sub") if isinstance(claims, dict) else None
        if not isinstance(sub, str) or not sub:
            raise KeylessError("the identity token names no subject")
        return sub


class Keyless:
    """`Keyless().sign_dsse(payload_type, payload, token)` -> a verified Sigstore bundle (dict)."""

    #: Sigstore's public instances: production, and staging (for conformance checks only).
    INSTANCES: ClassVar[dict[str, tuple[str, str]]] = {
        "production": (
            "https://fulcio.sigstore.dev/api/v2/signingCert",
            "https://rekor.sigstore.dev/api/v1/log/entries",
        ),
        "staging": (
            "https://fulcio.sigstage.dev/api/v2/signingCert",
            "https://rekor.sigstage.dev/api/v1/log/entries",
        ),
    }
    MEDIA_TYPE: ClassVar[str] = "application/vnd.dev.sigstore.bundle.v0.3+json"

    def __init__(self, post: Any = None, *, instance: str = "production", root: Any = None) -> None:
        self.fulcio, self.rekor = Keyless.INSTANCES[instance]
        #: `post(url, document) -> dict`, the one network operation; replaceable in a test.
        self.post = post or self._post
        #: The trust root the returned bundle is verified against (the pinned production one).
        self.root = root

    def sign_dsse(self, payload_type: str, payload: bytes, token: str) -> dict[str, Any]:
        from cordon_scanner.intel.provenance.sigstore_bundle import (
            BundleError,
            BundleVerifier,
            Rejected,
        )

        key = P256Signer.ephemeral()
        chain = self._certificate(key, token)
        leaf_der = Keyless._der(chain[0])
        pae = Keyless.pae(payload_type, payload)
        signature = key.sign(pae)
        del key  # used once
        envelope = {
            "payload": base64.b64encode(payload).decode(),
            "payloadType": payload_type,
            "signatures": [{"sig": base64.b64encode(signature).decode()}],
        }
        entry = self._log(envelope, chain[0])
        bundle = {
            "mediaType": Keyless.MEDIA_TYPE,
            "verificationMaterial": {
                "certificate": {"rawBytes": base64.b64encode(leaf_der).decode()},
                "tlogEntries": [entry],
            },
            "dsseEnvelope": envelope,
        }
        try:
            BundleVerifier(self.root).verify(json.dumps(bundle))
        except (BundleError, Rejected) as exc:
            raise KeylessError(f"the bundle Sigstore returned does not verify: {exc}") from exc
        return bundle

    # -- Fulcio ---------------------------------------------------------------

    def _certificate(self, key: P256Signer, token: str) -> list[str]:
        proof = key.sign(OidcToken.subject(token).encode())
        reply = self.post(
            self.fulcio,
            {
                "credentials": {"oidcIdentityToken": token},
                "publicKeyRequest": {
                    "publicKey": {"algorithm": "ECDSA", "content": key.public_pem()},
                    "proofOfPossession": base64.b64encode(proof).decode(),
                },
            },
        )
        signed = reply.get("signedCertificateEmbeddedSct") if isinstance(reply, dict) else None
        chain = ((signed or {}).get("chain") or {}).get("certificates")
        if not isinstance(chain, list) or not chain or not all(isinstance(c, str) for c in chain):
            raise KeylessError("Fulcio returned no certificate with an embedded timestamp")
        return chain

    # -- Rekor ----------------------------------------------------------------

    def _log(self, envelope: dict[str, Any], leaf_pem: str) -> dict[str, Any]:
        reply = self.post(
            self.rekor,
            {
                "apiVersion": "0.0.1",
                "kind": "dsse",
                "spec": {
                    "proposedContent": {
                        "envelope": json.dumps(envelope, separators=(",", ":")),
                        "verifiers": [base64.b64encode(leaf_pem.encode()).decode()],
                    }
                },
            },
        )
        if not isinstance(reply, dict) or len(reply) != 1:
            raise KeylessError("Rekor returned no single entry")
        (logged,) = reply.values()
        try:
            proof = logged["verification"]["inclusionProof"]
            return {
                "logIndex": str(int(logged["logIndex"])),
                "logId": {"keyId": base64.b64encode(bytes.fromhex(logged["logID"])).decode()},
                "kindVersion": {"kind": "dsse", "version": "0.0.1"},
                "integratedTime": str(int(logged["integratedTime"])),
                "inclusionPromise": {
                    "signedEntryTimestamp": logged["verification"]["signedEntryTimestamp"]
                },
                "inclusionProof": {
                    "logIndex": str(int(proof["logIndex"])),
                    "rootHash": base64.b64encode(bytes.fromhex(proof["rootHash"])).decode(),
                    "treeSize": str(int(proof["treeSize"])),
                    "hashes": [
                        base64.b64encode(bytes.fromhex(h)).decode() for h in proof["hashes"]
                    ],
                    "checkpoint": {"envelope": proof["checkpoint"]},
                },
                "canonicalizedBody": logged["body"],
            }
        except (KeyError, TypeError, ValueError) as exc:
            raise KeylessError(f"Rekor's entry is not in the expected form ({exc})") from exc

    # -- helpers ----------------------------------------------------------------

    @staticmethod
    def pae(payload_type: str, payload: bytes) -> bytes:
        kind = payload_type.encode()
        return b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(payload), payload)

    @staticmethod
    def _der(pem: str) -> bytes:
        from cordon_scanner.intel.provenance.x509 import Pem

        return Pem.decode(pem, "CERTIFICATE")

    def _post(self, url: str, document: dict[str, Any]) -> Any:
        if url not in (self.fulcio, self.rekor):
            raise KeylessError(f"not a Sigstore endpoint: {url}")
        request = urllib.request.Request(  # noqa: S310 - one of two fixed https endpoints
            url,
            data=json.dumps(document).encode(),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
                return json.loads(Download.read(response, MAX_TOKEN_REPLY_BYTES))
        except (OSError, ValueError) as exc:
            raise KeylessError(
                f"{urllib.parse.urlsplit(url).netloc} could not be reached ({type(exc).__name__})"
            ) from exc


__all__ = ["Keyless", "KeylessError", "OidcToken"]
