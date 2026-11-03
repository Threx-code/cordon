"""Why a network call failed, in words a user can act on (item 50).

Every fetch reduced its failure to the exception's type name: on python.org's macOS Python, which
ships without trusted CA certificates until `Install Certificates.command` is run, the first scan
reported its intelligence STALE "(URLError)" and said nothing about why. A certificate that cannot
be verified is now named, with the fix; every other failure says its type name and its own cause
(item 52's sweep: an offline `advisories sync` said only "URLError"). What the scan does about a failed fetch -- stale, fail-closed -- is the
caller's and is unchanged.
"""

from __future__ import annotations

import ssl
from typing import ClassVar


class NetworkFailure:
    """`reason(exc)`: what to say in place of `type(exc).__name__` for a failed network call."""

    CERTIFICATE: ClassVar[str] = (
        "the server's TLS certificate could not be verified: this Python has no trusted CA "
        "certificates. On python.org's macOS Python, run 'Install Certificates.command' in its "
        "Applications folder; elsewhere, set SSL_CERT_FILE to a CA bundle"
    )
    #: How deep a chain of wrapped exceptions is followed (URLError.reason, __cause__, __context__).
    MAX_DEPTH: ClassVar[int] = 8

    @staticmethod
    def certificate(exc: BaseException) -> bool:
        """Whether the failure is, at any depth of wrapping, a certificate that did not verify."""
        current: BaseException | None = exc
        for _ in range(NetworkFailure.MAX_DEPTH):
            if current is None:
                return False
            if isinstance(current, ssl.SSLCertVerificationError):
                return True
            if "CERTIFICATE_VERIFY_FAILED" in str(current):
                return True
            reason = getattr(current, "reason", None)
            if isinstance(reason, BaseException):
                current = reason  # urllib's URLError wraps the SSL error as its reason
                continue
            current = current.__cause__ or current.__context__
        return False

    #: How much of an underlying cause is said: one line, bounded.
    MAX_CAUSE: ClassVar[int] = 200

    @staticmethod
    def cause(exc: BaseException) -> str:
        """What the failure says about itself: urllib's wrapped reason, or an OSError's own
        message (`Temporary failure in name resolution`, `Connection refused`), on one line."""
        reason = getattr(exc, "reason", None)
        inner = reason if reason is not None else exc
        words = [a for a in getattr(inner, "args", ()) if isinstance(a, str)]
        # An OSError's message, else its own words (an `SSLError` of one argument prints its
        # argument tuple), else what it prints.
        text = getattr(inner, "strerror", None) or " ".join(words) or str(inner)
        return " ".join(str(text).split())[: NetworkFailure.MAX_CAUSE]

    @staticmethod
    def reason(exc: BaseException) -> str:
        """The certificate's cause and fix; otherwise the exception's type name with its cause, so
        an offline `advisories sync` says why it failed, not only `URLError` (item 52)."""
        if NetworkFailure.certificate(exc):
            return NetworkFailure.CERTIFICATE
        cause = NetworkFailure.cause(exc)
        return f"{type(exc).__name__}: {cause}" if cause else type(exc).__name__


__all__ = ["NetworkFailure"]
