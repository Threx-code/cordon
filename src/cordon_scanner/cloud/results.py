"""K2: scan results, bound to what was scanned and who scanned it, uploaded to the cloud.

The results are the JSON report's own bytes (`--format json`, canonical and timestamp-free). An
in-toto Statement v1 names their SHA-256 as its subject and carries a predicate of what the cloud
needs without parsing the results: the target, the verdict, the counts and every finding's
fingerprint (K1). The statement travels in a DSSE envelope.

In CI with `sigstore` installed (`[attest]`), the envelope is signed keylessly: Fulcio certifies the
job's OIDC identity -- repository, workflow, commit -- and Rekor logs the signature, so the cloud
can check that the results came from the run they claim. Elsewhere the envelope is unsigned and
the upload is vouched for by the sign-in token alone; `signing` in the upload says which, and the
cloud records the difference rather than treating the two as equal.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from cordon_scanner.cloud import CloudError
from cordon_scanner.cloud.transport import CloudTransport, Transport
from cordon_scanner.version import __version__

if TYPE_CHECKING:
    from cordon_scanner.cloud.auth import Credentials
    from cordon_scanner.core.models import ScanResult

STATEMENT_TYPE: Final = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE: Final = "https://cordon.dev/attestations/scan-results/v1"
PAYLOAD_TYPE: Final = "application/vnd.in-toto+json"
UPLOAD_SCHEMA: Final = "cordon.upload/v1"
SUBJECT_NAME: Final = "cordon-results.json"


class SignedResults:
    """Scan results as a signed statement, and their upload."""

    @staticmethod
    def results_bytes(result: ScanResult) -> bytes:
        """The results exactly as `--format json` writes them, suppressed findings included."""
        return (
            json.dumps(result.to_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        ).encode()

    @staticmethod
    def ai_inventory(root: Path, result: ScanResult) -> dict[str, Any] | None:
        """The scanned tree's AI-BOM, to travel with its results: agents, MCP servers, skills, prompts
        and models as names, paths, hashes and package ids. No file contents. None when the target is
        not a directory or the inventory cannot be built; an upload never fails for want of one."""
        if not root.is_dir():
            return None
        try:
            from cordon_scanner.notify import Webhooks
            from cordon_scanner.report import aibom

            repository = result.repository
            return aibom.AiBom.cyclonedx_document(
                root,
                result.dependencies,
                root_name=Webhooks._target_name(result),
                root_version=(repository.revision if repository else None) or "unversioned",
                tool_version=__version__,
            )
        except Exception:
            return None

    @staticmethod
    def ai_inventory_bytes(document: dict[str, Any]) -> bytes:
        return json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()

    @staticmethod
    def statement(
        result: ScanResult,
        results: bytes,
        *,
        exit_code: int,
        reason: str,
        ai_inventory: bytes | None = None,
    ) -> dict[str, Any]:
        from cordon_scanner.notify import Webhooks

        repository = result.repository
        severities = Counter(
            f.severity.name.lower() for f in result.findings if not f.is_suppressed
        )
        return {
            "_type": STATEMENT_TYPE,
            "subject": [
                {"name": SUBJECT_NAME, "digest": {"sha256": hashlib.sha256(results).hexdigest()}}
            ],
            "predicateType": PREDICATE_TYPE,
            "predicate": {
                "scanner": {
                    "name": "cordon-scanner",
                    "version": __version__,
                    "rulepack_hash": result.rulepack_hash,
                },
                "target": {
                    "name": Webhooks._target_name(result),
                    "revision": (repository.revision if repository else None) or "",
                    "branch": (repository.branch if repository else None) or "",
                },
                "verdict": {"exit_code": exit_code, "reason": reason, "complete": result.complete},
                "summary": {
                    "findings": sum(severities.values()),
                    "suppressed": sum(1 for f in result.findings if f.is_suppressed),
                    "by_severity": dict(sorted(severities.items())),
                },
                "fingerprints": sorted({f.fingerprint for f in result.findings}),
                # The AI-BOM sent beside the results, bound by digest so the signature covers it too.
                **(
                    {"ai_inventory": {"sha256": hashlib.sha256(ai_inventory).hexdigest()}}
                    if ai_inventory is not None
                    else {}
                ),
            },
        }

    @staticmethod
    def pae(payload_type: str, payload: bytes) -> bytes:
        """DSSE's pre-authentication encoding: what a signature over an envelope actually covers."""
        kind = payload_type.encode()
        return b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(payload), payload)

    @staticmethod
    def sigstore_signer(identity_token: str | None) -> Signer:
        """A keyless signer, when `sigstore` is installed. With no token given, sigstore asks the CI
        for one with its own audience -- a token minted for Cordon is not one Fulcio accepts."""

        def sign(payload: bytes) -> dict[str, Any] | None:
            try:
                from sigstore import dsse
                from sigstore.oidc import IdentityToken, detect_credential
                from sigstore.sign import SigningContext
            except ImportError:
                return None
            raw = identity_token or detect_credential()
            if not raw:
                return None
            # sigstore 3 builds the public-good context directly; 4 builds it from a trust config.
            legacy = getattr(SigningContext, "production", None)
            if legacy is not None:
                context = legacy()
            else:
                from sigstore.models import ClientTrustConfig

                context = SigningContext.from_trust_config(ClientTrustConfig.production())
            with context.signer(IdentityToken(raw), cache=True) as signer:
                bundle = signer.sign_dsse(dsse.Statement(payload))
            return dict(json.loads(bundle.to_json()))

        return sign

    @staticmethod
    def sign(statement_document: dict[str, Any], signer: Signer | None) -> Signed:
        payload = json.dumps(statement_document, sort_keys=True, separators=(",", ":")).encode()
        envelope = {
            "payloadType": PAYLOAD_TYPE,
            "payload": base64.b64encode(payload).decode(),
            "signatures": [],
        }
        bundle = signer(payload) if signer is not None else None
        if bundle is None:
            return Signed(envelope, "none")
        return Signed(envelope, "sigstore", bundle)

    @staticmethod
    def upload(
        result: ScanResult,
        credentials: Credentials,
        *,
        exit_code: int,
        reason: str,
        signer: Signer | None = None,
        transport: Transport | None = None,
        ai_document: dict[str, Any] | None = None,
    ) -> Receipt:
        results = SignedResults.results_bytes(result)
        inventory = (
            SignedResults.ai_inventory_bytes(ai_document) if ai_document is not None else None
        )
        signed = SignedResults.sign(
            SignedResults.statement(
                result, results, exit_code=exit_code, reason=reason, ai_inventory=inventory
            ),
            signer,
        )
        body: dict[str, Any] = {
            "schema": UPLOAD_SCHEMA,
            "org": credentials.org,
            "results": base64.b64encode(results).decode(),
            "envelope": signed.envelope,
            "signing": signed.signing,
        }
        if signed.bundle is not None:
            body["sigstore_bundle"] = signed.bundle
        if inventory is not None:
            body["ai_inventory"] = base64.b64encode(inventory).decode()
        response = CloudTransport.request(
            "POST",
            f"{credentials.url}/v1/scans",
            json_body=body,
            token=credentials.access_token,
            transport=transport,
        )
        if response.status not in (200, 201, 202):
            raise CloudError(f"the upload was refused: {CloudTransport.error_text(response)}")
        return Receipt(
            str(response.body.get("scan_id", "")), str(response.body.get("url", "")), signed.signing
        )


@dataclass(frozen=True)
class Signed:
    envelope: dict[str, Any]
    signing: str
    """`sigstore` (keyless, CI identity) or `none` (vouched for by the sign-in token only)."""
    bundle: dict[str, Any] | None = None


Signer = Callable[[bytes], dict[str, Any] | None]
"""Takes the statement bytes; returns a Sigstore bundle as JSON, or None when it cannot sign."""


@dataclass(frozen=True)
class Receipt:
    scan_id: str
    url: str
    signing: str


__all__ = ["PAYLOAD_TYPE", "PREDICATE_TYPE", "Receipt", "Signed", "SignedResults"]
