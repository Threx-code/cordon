"""Terraform providers' signed checksums, verified as `terraform init` verifies them.

A provider release on the public registry is published as zip files plus a `SHA256SUMS` file that lists every
zip's SHA-256, and a detached OpenPGP signature of that file. The registry's own answer names all three, and the
public keys the publisher registered:

    GET https://registry.terraform.io/v1/providers/<namespace>/<type>/<version>/download/<os>/<arch>
        shasum, shasums_url, shasums_signature_url, signing_keys.gpg_public_keys[].ascii_armor

The check is `terraform init`'s: the detached signature must verify over `SHA256SUMS`, and the archive the lock file
pinned (`zh:<hex>`, the SHA-256 of a platform's zip) must be one of the signed lines. What it says about trust
is the level it can prove, and the finding names it:

* the signature verifies under a key in the operator's keyring (`--keyring`): `verified`;
* it verifies only under a key the registry itself serves, which this scan has no reason to trust: `unconfigured`
  ("signed by key X, which the registry serves; add it to the keyring to trust it");
* it verifies under neither, or the signed sums do not list the locked zip: `invalid`.

Bounded and honest about what it cannot answer: a lock file that pins only `h1:` (a package-contents hash) has no zip hash
to compare, so the answer is `unverifiable`; a release with no signature file is `absent`. Network use is the scan's
`--online` only, over HTTPS.
"""

from __future__ import annotations

import http.client
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from cordon_scanner.foundation.network.downloads import Download
from cordon_scanner.foundation.network.failures import NetworkFailure
from cordon_scanner.foundation.network.redirects import ClosedErrors, HttpsRedirects
from cordon_scanner.intel.provenance import openpgp

API: Final = (
    "https://registry.terraform.io/v1/providers/{namespace}/{kind}/{version}/download/linux/amd64"
)
TIMEOUT: Final = 15.0
MAX_ANSWER_BYTES: Final = 1 << 20
MAX_SUMS_BYTES: Final = 1 << 20
_NAME: Final = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
_VERSION: Final = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+-]{0,63}")
_SUM_LINE: Final = re.compile(r"^([0-9a-f]{64})[ \t]+\*?(\S+)$")


@dataclass(frozen=True)
class ProviderCheck:
    outcome: str
    """`verified`, `invalid`, `unverifiable`, `unconfigured` (signed; no key of the operator's holds it) or `absent`."""
    detail: str


class TerraformProvenance:
    @staticmethod
    def _get(url: str, limit: int) -> bytes | None:
        """The body, or None where the server has no such file."""
        if urllib.parse.urlsplit(url).scheme != "https":
            raise ValueError("not https")
        request = urllib.request.Request(url, headers={"User-Agent": "cordon-scanner"})  # noqa: S310 - https only
        opener = urllib.request.build_opener(HttpsRedirects, ClosedErrors)
        try:
            with opener.open(request, timeout=TIMEOUT) as response:
                body: bytes = Download.read(response, limit + 1)
        except urllib.error.HTTPError as exc:
            NetworkFailure.release(exc)
            if exc.code in (403, 404, 410):
                return None
            raise
        if len(body) > limit:
            raise ValueError("response too large")
        return body

    @staticmethod
    def signed_sums(text: bytes) -> dict[str, str] | None:
        """`{sha256 hex: file name}` of each line of a `SHA256SUMS` file; None where a line is not one."""
        sums: dict[str, str] = {}
        for line in text.decode("utf-8", "replace").splitlines():
            if not line.strip():
                continue
            found = _SUM_LINE.match(line.strip())
            if found is None:
                return None
            sums[found.group(1)] = found.group(2)
        return sums or None

    @staticmethod
    def served_keys(answer: dict[str, Any]) -> openpgp.Keyring:
        """The keys the registry's answer serves, as a keyring that names no file."""
        keys = ((answer.get("signing_keys") or {}).get("gpg_public_keys")) or []
        armor = b"\n".join(
            k["ascii_armor"].encode("utf-8")
            for k in keys
            if isinstance(k, dict) and isinstance(k.get("ascii_armor"), str)
        )
        return openpgp.OpenPgp.from_bytes(armor, "the registry's answer")

    @classmethod
    def check(
        cls, name: str, version: str, integrity: str | None, keyring: openpgp.Keyring
    ) -> ProviderCheck:
        """The provider's signed checksums: signed by a key, listing the zip the lock file pinned."""
        label = f"{name} {version}"
        namespace, _, kind = name.partition("/")
        if not (_NAME.fullmatch(namespace) and _NAME.fullmatch(kind) and "/" not in kind):
            return ProviderCheck("unverifiable", f"{name} is not a namespace/type provider address")
        if not _VERSION.fullmatch(version):
            return ProviderCheck("unverifiable", f"{version} is not a version the registry serves")
        try:
            body = cls._get(
                API.format(namespace=namespace, kind=kind, version=version), MAX_ANSWER_BYTES
            )
            if body is None:
                return ProviderCheck("unverifiable", f"the registry does not hold {label}")
            answer = json.loads(body)
            sums_url, sig_url = answer.get("shasums_url"), answer.get("shasums_signature_url")
            if not isinstance(answer, dict) or not isinstance(sums_url, str):
                return ProviderCheck(
                    "unverifiable", "the registry's answer names no checksums file"
                )
            if not isinstance(sig_url, str) or not sig_url:
                return ProviderCheck("absent", f"{label} is published without a signature file")
            sums_bytes = cls._get(sums_url, MAX_SUMS_BYTES)
            signature = cls._get(sig_url, MAX_SUMS_BYTES)
        except (
            urllib.error.URLError,
            http.client.HTTPException,
            OSError,
            ValueError,
        ) as exc:
            return ProviderCheck(
                "unverifiable", f"the registry could not be read ({NetworkFailure.reason(exc)})"
            )
        if sums_bytes is None:
            return ProviderCheck("unverifiable", f"{sums_url} could not be downloaded")
        if signature is None:
            return ProviderCheck("absent", f"{label} is published without a signature file")
        return cls._judge(label, answer, sums_bytes, signature, integrity, keyring)

    @classmethod
    def _judge(
        cls,
        label: str,
        answer: dict[str, Any],
        sums_bytes: bytes,
        signature: bytes,
        integrity: str | None,
        keyring: openpgp.Keyring,
    ) -> ProviderCheck:
        trusted = (
            openpgp.OpenPgp.verify(sums_bytes, keyring, signature=signature) if keyring else None
        )
        served_keys = cls.served_keys(answer)
        served = openpgp.OpenPgp.verify(sums_bytes, served_keys, signature=signature)
        by_keyring = trusted is not None and trusted.outcome is openpgp.Outcome.VERIFIED
        winner = trusted if by_keyring else served
        if winner is None or winner.outcome is not openpgp.Outcome.VERIFIED:
            why = (trusted or served).detail if (trusted or served) else "no key"
            return ProviderCheck(
                "invalid", f"its signature does not verify over the checksums file: {why}"
            )
        if winner.expires is not None and winner.expires <= datetime.now(UTC):
            return ProviderCheck(
                "invalid",
                f"its checksums are signed by {winner.signer}, a key that expired on "
                f"{winner.expires:%Y-%m-%d}",
            )
        sums = cls.signed_sums(sums_bytes)
        if sums is None:
            return ProviderCheck(
                "invalid", "the signed checksums file is not a list of SHA-256 sums"
            )
        served_sum = answer.get("shasum")
        if isinstance(served_sum, str) and served_sum not in sums:
            return ProviderCheck(
                "invalid", "the registry's own checksum for the zip is not in the signed list"
            )
        pinned = (integrity or "")[3:] if (integrity or "").startswith("zh:") else None
        if pinned is None:
            return ProviderCheck(
                "unverifiable",
                "the lock file holds no zip hash (zh:) to compare with the signed checksums",
            )
        if pinned not in sums:
            return ProviderCheck(
                "invalid", "the zip hash the lock file pinned is in no line of the signed checksums"
            )
        if not by_keyring:
            return ProviderCheck(
                "unconfigured",
                f"{label}: the checksums are signed by key {winner.signer}, which the registry serves; "
                "it is not in your keyring (--keyring), so who signed them is not established",
            )
        return ProviderCheck(
            "verified",
            f"{label}: {winner.detail}, over a checksums file that lists the locked zip",
        )


__all__ = ["ProviderCheck", "TerraformProvenance"]
