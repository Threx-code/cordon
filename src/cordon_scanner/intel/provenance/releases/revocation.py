"""Certificate revocation, read from the certificate revocation list a certificate names.

A signature by a certificate its authority has since revoked proves less than one by a certificate in good standing. Each
certificate here names where its issuer publishes the list (CRL distribution points). The list is fetched from there (a
bounded read, over a connection that goes only to a public address), must be signed by the issuer, must be current, and
must not name the certificate's serial. The URL is trusted only because the certificate naming it was verified first; the
list is trusted only by the issuer's signature.

What was consulted is always said: `checked`, `unavailable: <why>` (the list could not be had or read, so the gap is
named, not hidden), or `not consulted` (no fetcher: an offline scan)."""

from __future__ import annotations

import datetime as dt
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import ClassVar

from cordon_scanner.foundation.network.downloads import Download
from cordon_scanner.foundation.network.failures import NetworkFailure
from cordon_scanner.foundation.network.pinned import PinnedHTTP
from cordon_scanner.foundation.network.redirects import NoRedirects
from cordon_scanner.foundation.signatures.der import Der, DerError
from cordon_scanner.intel.provenance.x509 import Certificate

Fetcher = Callable[[str], bytes]


class RevocationError(ValueError):
    """The list could not be read or trusted."""


@dataclass(frozen=True)
class Crl:
    issuer: bytes
    this_update: dt.datetime
    next_update: dt.datetime | None
    revoked: frozenset[int]
    tbs: bytes
    algorithm: str
    signature: bytes

    UTC_TIME: ClassVar[int] = 0x17
    GENERALIZED_TIME: ClassVar[int] = 0x18
    DELTA: ClassVar[str] = "2.5.29.27"
    ISSUING_DISTRIBUTION_POINT: ClassVar[str] = "2.5.29.28"
    MAX_ENTRIES: ClassVar[int] = 2_000_000
    UNDERSTOOD: ClassVar[frozenset[str]] = frozenset({"2.5.29.20", "2.5.29.35"})

    @classmethod
    def parse(cls, raw: bytes) -> Crl:
        try:
            outer = Der.parse(raw, Der.SEQUENCE).children()
            if len(outer) != 3:
                raise RevocationError("a revocation list of the wrong shape")
            tbs = outer[0].expect(Der.SEQUENCE)
            fields = tbs.children()
            at = 1 if fields[0].tag == Der.INTEGER else 0
            algorithm = outer[1].expect(Der.SEQUENCE).children()[0].oid()
            issuer = fields[at + 1].expect(Der.SEQUENCE).raw
            this_update = Certificate._time(fields[at + 2])
            at += 3
            next_update = None
            if at < len(fields) and fields[at].tag in (cls.UTC_TIME, cls.GENERALIZED_TIME):
                next_update = Certificate._time(fields[at])
                at += 1
            revoked: set[int] = set()
            if at < len(fields) and fields[at].tag == Der.SEQUENCE:
                entries = fields[at].children()
                if len(entries) > cls.MAX_ENTRIES:
                    raise RevocationError("a revocation list past any real size")
                revoked = {entry.expect(Der.SEQUENCE).children()[0].integer() for entry in entries}
                at += 1
            if at < len(fields) and fields[at].tag == 0xA0:
                for extension in Der.parse(fields[at].body, Der.SEQUENCE).children():
                    cls._extension(extension)
            return cls(
                issuer,
                this_update,
                next_update,
                frozenset(revoked),
                tbs.raw,
                algorithm,
                outer[2].bit_string(),
            )
        except (DerError, IndexError, ValueError) as exc:
            if isinstance(exc, RevocationError):
                raise
            raise RevocationError(f"not a revocation list: {exc}") from exc

    @classmethod
    def _extension(cls, extension: Der) -> None:
        """A list that is a delta, or limited to some kinds of certificate or reasons, does not name every revoked serial: refused."""
        parts = extension.expect(Der.SEQUENCE).children()
        oid = parts[0].oid()
        critical = len(parts) == 3 and parts[1].body == b"\xff"
        if oid == cls.DELTA:
            raise RevocationError("a delta list, which does not name every revoked serial")
        if oid == cls.ISSUING_DISTRIBUTION_POINT:
            # Only a named distribution point is allowed: the other fields narrow the list to user or CA certificates, some
            # reasons, indirect issuers or attribute certificates.
            scope = Der.parse(parts[-1].body, Der.SEQUENCE).children()
            if any(item.tag != 0xA0 for item in scope):
                raise RevocationError("a partial list (limited by kind, reason or issuer)")
        elif critical and oid not in cls.UNDERSTOOD:
            raise RevocationError("a list with a critical extension not understood")


class Revocation:
    CRL_DISTRIBUTION_POINTS: ClassVar[str] = "2.5.29.31"
    MAX_BYTES: ClassVar[int] = 16 << 20
    MAX_URLS: ClassVar[int] = 4
    TIMEOUT: ClassVar[float] = 20.0
    _cache: ClassVar[dict[str, Crl]] = {}

    @classmethod
    def urls(cls, certificate: Certificate) -> list[str]:
        held = certificate.extensions.get(cls.CRL_DISTRIBUTION_POINTS)
        if held is None:
            return []
        found: list[str] = []
        for point in Der.parse(held.value, Der.SEQUENCE).children():
            for part in point.children():
                if part.tag != 0xA0:  # distributionPoint
                    continue
                for name in part.children():
                    if name.tag == 0xA0:  # fullName
                        found.extend(
                            general.body.decode("ascii", "replace")
                            for general in name.children()
                            if general.tag == 0x86
                        )
        return [u for u in found if u.startswith("http://")][: cls.MAX_URLS]

    @classmethod
    def fetch(cls, url: str) -> bytes:
        request = urllib.request.Request(url, headers={"User-Agent": "cordon-scanner"})  # noqa: S310 - http, checked by the caller
        opener = urllib.request.build_opener(NoRedirects, PinnedHTTP)
        with opener.open(request, timeout=cls.TIMEOUT) as response:
            body: bytes = Download.read(response, cls.MAX_BYTES + 1)
        if len(body) > cls.MAX_BYTES:
            raise RevocationError("a revocation list past the size cap")
        return body

    @classmethod
    def status(
        cls,
        certificate: Certificate,
        issuer: Certificate,
        fetcher: Fetcher | None,
        now: dt.datetime,
    ) -> str:
        """`checked`, `revoked`, `not consulted`, or `unavailable: <why>` for `certificate`, against the list its issuer publishes."""
        if fetcher is None:
            return "not consulted"
        try:
            urls = cls.urls(certificate)
        except (DerError, ValueError):
            return "unavailable: the certificate's distribution points are unreadable"
        if not urls:
            return "unavailable: the certificate names no revocation list"
        reasons: list[str] = []
        for url in urls:
            try:
                crl = cls._current(url, issuer, fetcher, now)
            except (RevocationError, DerError, ValueError, OSError, urllib.error.URLError) as exc:
                reasons.append(NetworkFailure.reason(exc) if isinstance(exc, OSError) else str(exc))
                continue
            return "revoked" if certificate.serial in crl.revoked else "checked"
        return f"unavailable: {'; '.join(reasons)}"

    @classmethod
    def _current(cls, url: str, issuer: Certificate, fetcher: Fetcher, now: dt.datetime) -> Crl:
        cached = cls._cache.get(url)
        if cached is not None and cached.next_update is not None and now < cached.next_update:
            return cached
        crl = Crl.parse(fetcher(url))
        if crl.issuer != issuer.subject:
            raise RevocationError("the list is not the issuer's")
        if not issuer.public_key().verify_algorithm(crl.algorithm, crl.tbs, crl.signature):
            raise RevocationError("the list's signature does not verify under the issuer's key")
        if crl.this_update > now or crl.next_update is None or now >= crl.next_update:
            raise RevocationError("the list is not current")
        cls._cache[url] = crl
        return crl
