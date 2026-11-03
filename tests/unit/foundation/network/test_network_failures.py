"""Item 50: a certificate that cannot be verified is named, with its fix, wherever a fetch fails.

User report on v0.6.0: on python.org's macOS Python (no trusted CA certificates until
`Install Certificates.command` is run) the first scan's intelligence was STALE "(URLError)", with
no reason. Every other failure keeps its type name, and the scan stays stale and fail-closed.
"""

from __future__ import annotations

import ssl
import urllib.error

import pytest

from cordon_scanner.foundation.network.failures import NetworkFailure
from cordon_scanner.intel.malware.feed import FeedClient, FeedError


class CertificateKit:
    @staticmethod
    def unverified() -> urllib.error.URLError:
        cause = ssl.SSLCertVerificationError(
            1,
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer",
        )
        return urllib.error.URLError(cause)


class TestTheReason:
    def test_an_unverified_certificate_is_named_with_its_fix(self) -> None:
        said = NetworkFailure.reason(CertificateKit.unverified())
        assert "certificate could not be verified" in said
        assert "Install Certificates.command" in said
        assert "SSL_CERT_FILE" in said

    def test_a_certificate_error_wrapped_again_is_still_found(self) -> None:
        try:
            try:
                raise CertificateKit.unverified()
            except urllib.error.URLError as inner:
                raise OSError("fetch failed") from inner
        except OSError as outer:
            assert NetworkFailure.certificate(outer)

    @pytest.mark.parametrize(
        ("exc", "said"),
        [
            (
                urllib.error.URLError(OSError(-3, "Temporary failure in name resolution")),
                "URLError: Temporary failure in name resolution",
            ),
            (
                urllib.error.URLError("Name or service not known"),
                "URLError: Name or service not known",
            ),
            (
                ConnectionRefusedError(111, "Connection refused"),
                "ConnectionRefusedError: Connection refused",
            ),
            (ssl.SSLError("wrong version number"), "SSLError: wrong version number"),
        ],
    )
    def test_any_other_failure_says_its_cause(self, exc: BaseException, said: str) -> None:
        # `advisories sync` offline said only "URLError" (item 52's sweep): not why.
        assert NetworkFailure.reason(exc) == said

    def test_a_failure_with_nothing_to_say_keeps_its_type_name(self) -> None:
        assert NetworkFailure.reason(TimeoutError()) == "TimeoutError"

    def test_the_cause_is_one_bounded_line(self) -> None:
        said = NetworkFailure.reason(urllib.error.URLError("a\nb" + "x" * 500))
        assert "\n" not in said
        assert len(said) <= len("URLError: ") + NetworkFailure.MAX_CAUSE


class TestTheFeedSaysIt:
    def test_the_feed_fetch_names_the_certificate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class Refusing:
            def open(self, request, timeout=None):
                raise CertificateKit.unverified()

        monkeypatch.setattr("urllib.request.build_opener", lambda *handlers: Refusing())
        with pytest.raises(FeedError, match=r"Install Certificates\.command"):
            FeedClient._fetch("https://feed.invalid/meta.json", 1.0, 1024)
