"""Ansible collections' signatures, checked as `ansible-galaxy` checks them.

A collection is signed by detached OpenPGP signatures over its MANIFEST.json (which lists every
file with its SHA-256), checked against the keyring the operator gives (`ansible-galaxy
--keyring`; here `--keyring`). `ansible-galaxy` gathers them from three places
(`lib/ansible/galaxy/collection/__init__.py`, `api.py`, `concrete_artifact_manager.py`):

    a Galaxy server's version record   `signatures: [{signature: ...}]`, with the artifact's
                                       `download_url` and `artifact.sha256`
    a requirements.yml collection      `signatures:`, a URL each (`get_signature_from_source`)
    an installed collection            `<ns>.<name>-<version>.info/GALAXY.yml`, what the
                                       install recorded from the server

and passes a collection when at least one signature verifies (`GALAXY_REQUIRED_VALID_SIGNATURE_
COUNT` is 1 by default), failing it on a signature none of whose keys it holds (`NO_PUBKEY`), on
one that does not verify (`BADSIG`), and on a key that has expired (`EXPKEYSIG`).

Measured in October 2026: galaxy.ansible.com served no signature for any of 600 collections, and
no public requirements file in Sourcegraph's index lists any; signed collections are served by
private Galaxy NG and Automation Hub servers. Network use is the scan's `--online` only, over
HTTPS: galaxy.ansible.com, the artifact host it redirects to, and the URLs a requirements file
names.
"""

from __future__ import annotations

import hashlib
import http.client
import io
import json
import tarfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from cordon_scanner.intel import openpgp

GALAXY: Final = "https://galaxy.ansible.com"
VERSION: Final = (
    GALAXY + "/api/v3/plugin/ansible/content/published/collections/index/{ns}/{name}/versions/{v}/"
)
TIMEOUT: Final = 30.0
MAX_RECORD_BYTES: Final = 8 << 20
MAX_SIGNATURE_BYTES: Final = 64 << 10
MAX_ARTIFACT_BYTES: Final = 128 << 20
"""amazon.aws's artifact is a few megabytes; community.general's under ten."""
MAX_MANIFEST_BYTES: Final = 8 << 20


class _HttpsRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> Any:
        if urllib.parse.urlsplit(newurl).scheme != "https":
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@dataclass(frozen=True)
class CollectionCheck:
    outcome: str
    """`verified`, `invalid`, `unverifiable`, `unconfigured` (signed; no keyring) or `absent`."""
    detail: str


class AnsibleSignatures:
    @staticmethod
    def _get(url: str, limit: int) -> bytes:
        if urllib.parse.urlsplit(url).scheme != "https":
            raise ValueError("not https")
        request = urllib.request.Request(url, headers={"User-Agent": "cordon-scanner"})  # noqa: S310 - https only
        with urllib.request.build_opener(_HttpsRedirects).open(request, timeout=TIMEOUT) as r:
            body: bytes = r.read(limit + 1)
        if len(body) > limit:
            raise ValueError("response too large")
        return body

    @staticmethod
    def judge(
        manifest: bytes, signatures: tuple[str, ...], keyring: openpgp.Keyring, label: str
    ) -> CollectionCheck:
        """ansible-galaxy's rule: verified when one signature verifies, under a key that has not
        expired; otherwise the first failure."""
        if not signatures:
            return CollectionCheck("absent", f"{label} carries no signature")
        if not keyring and not keyring.paths:
            return CollectionCheck(
                "unconfigured",
                f"{label} is signed, but no keyring is configured to verify it against (--keyring)",
            )
        failures: list[openpgp.Result] = []
        for signature in signatures:
            result = openpgp.OpenPgp.verify(manifest, keyring, signature=signature.encode())
            if result.outcome is openpgp.Outcome.VERIFIED:
                if result.expires is not None and result.expires <= datetime.now(UTC):
                    # gpg's EXPKEYSIG, which ansible-galaxy counts as a failure.
                    failures.append(
                        openpgp.Result(
                            openpgp.Outcome.INVALID,
                            f"signed by {result.signer}, a key that expired on "
                            f"{result.expires:%Y-%m-%d} (EXPKEYSIG)",
                        )
                    )
                    continue
                return CollectionCheck("verified", f"{label}: {result.detail}, over MANIFEST.json")
            failures.append(result)
        worst = next((f for f in failures if f.outcome is openpgp.Outcome.INVALID), failures[0])
        return CollectionCheck(
            str(worst.outcome),
            f"none of {label}'s {len(signatures)} signature(s) verifies: {worst.detail}",
        )

    @staticmethod
    def installed(
        name: str,
        version: str,
        manifest: bytes,
        signatures: tuple[str, ...],
        keyring: openpgp.Keyring,
    ) -> CollectionCheck:
        """An installed collection: the signatures its install recorded, over its MANIFEST.json as
        it sits in the tree (`ansible-galaxy collection verify --offline`)."""
        return AnsibleSignatures.judge(manifest, signatures, keyring, f"{name} {version}")

    @staticmethod
    def remote(
        name: str, version: str, sources: tuple[str, ...], keyring: openpgp.Keyring
    ) -> CollectionCheck:
        """A collection a requirements file names: Galaxy's signatures and the requirement's own,
        over the MANIFEST.json of the artifact Galaxy serves, checked against its SHA-256."""
        label = f"{name} {version}"
        namespace, _, collection = name.partition(".")
        if not namespace or not collection or "." in collection:
            return CollectionCheck("absent", f"{name} is not a collection name")
        try:
            record = json.loads(
                AnsibleSignatures._get(
                    VERSION.format(
                        ns=urllib.parse.quote(namespace, safe=""),
                        name=urllib.parse.quote(collection, safe=""),
                        v=urllib.parse.quote(version, safe=""),
                    ),
                    MAX_RECORD_BYTES,
                )
            )
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return CollectionCheck("absent", f"Galaxy holds no {label}")
            return CollectionCheck("unverifiable", f"Galaxy answered HTTP {exc.code}")
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
            return CollectionCheck(
                "unverifiable", f"Galaxy could not be read ({type(exc).__name__})"
            )
        listed = record.get("signatures") if isinstance(record, dict) else None
        signatures = [
            str(item["signature"])
            for item in listed or ()
            if isinstance(item, dict) and isinstance(item.get("signature"), str)
        ]
        unread: list[str] = []
        for source in sources:
            if urllib.parse.urlsplit(source).scheme != "https":
                # A local path is the machine running ansible-galaxy's, not the repository's.
                unread.append(source)
                continue
            try:
                signatures.append(
                    AnsibleSignatures._get(source, MAX_SIGNATURE_BYTES).decode("utf-8", "replace")
                )
            except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
                return CollectionCheck(
                    "unverifiable",
                    f"the signature at {source} could not be read ({type(exc).__name__})",
                )
        if not signatures:
            if unread:
                return CollectionCheck(
                    "unverifiable",
                    f"{label}'s signature is at {unread[0]}, a path on the machine that installs it",
                )
            return CollectionCheck("absent", f"Galaxy serves no signature for {label}")
        if not keyring and not keyring.paths:
            return CollectionCheck(
                "unconfigured",
                f"{label} is signed, but no keyring is configured to verify it against (--keyring)",
            )
        artifact = record.get("artifact") if isinstance(record, dict) else None
        digest = artifact.get("sha256") if isinstance(artifact, dict) else None
        url = record.get("download_url") if isinstance(record, dict) else None
        if not isinstance(url, str) or not isinstance(digest, str):
            return CollectionCheck("unverifiable", f"Galaxy's record of {label} names no artifact")
        try:
            body = AnsibleSignatures._get(urllib.parse.urljoin(GALAXY, url), MAX_ARTIFACT_BYTES)
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
            return CollectionCheck(
                "unverifiable", f"{label}'s artifact could not be downloaded ({type(exc).__name__})"
            )
        if hashlib.sha256(body).hexdigest() != digest.lower():
            return CollectionCheck(
                "invalid", f"{label}'s artifact does not hash to the SHA-256 Galaxy records for it"
            )
        try:
            with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as archive:
                member = archive.getmember("MANIFEST.json")
                handle = archive.extractfile(member) if member.isfile() else None
                manifest = handle.read(MAX_MANIFEST_BYTES) if handle else b""
        except (tarfile.TarError, KeyError, OSError, EOFError):
            return CollectionCheck("invalid", f"{label}'s artifact holds no MANIFEST.json")
        return AnsibleSignatures.judge(manifest, tuple(signatures), keyring, label)


__all__ = ["AnsibleSignatures", "CollectionCheck"]
