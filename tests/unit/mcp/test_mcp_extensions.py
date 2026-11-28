"""An IDE extension fetched by identifier (`mcp/extensions`): checks, digests, refusals."""

from __future__ import annotations

import hashlib
import io
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.mcp import extensions
from cordon_scanner.mcp.extensions import ExtensionError, ExtensionFetcher

VSIX = b"PK\x03\x04 a pretend package"
DIGEST = hashlib.sha256(VSIX).hexdigest()


class _Kit_serve:
    @staticmethod
    def serve(monkeypatch: pytest.MonkeyPatch, answers: dict[str, bytes]) -> list[str]:
        """Replace the network read: each URL answers with its bytes, an unknown one is a 404."""
        asked: list[str] = []

        def fake(cls: Any, url: str, **_: Any) -> bytes:
            asked.append(url)
            if url not in answers:
                raise ExtensionError("the registry has no such extension or version")
            return answers[url]

        monkeypatch.setattr(ExtensionFetcher, "_get", classmethod(fake))
        return asked


serve = _Kit_serve.serve


class _Kit_vsx_meta:
    @staticmethod
    def vsx_meta(**files: str) -> bytes:
        return json.dumps({"version": "1.2.3", "files": files}).encode()


vsx_meta = _Kit_vsx_meta.vsx_meta


class TestCheck:
    def test_splits_publisher_and_name(self) -> None:
        assert ExtensionFetcher.check("ms-python.python", "1.0.0") == ("ms-python", "python")

    @pytest.mark.parametrize("name", ["nopublisher", "a.b/../c", ".x", "a b.c", ""])
    def test_refuses_a_bad_identifier(self, name: str) -> None:
        with pytest.raises(ExtensionError, match=r"publisher\.name"):
            ExtensionFetcher.check(name, None)

    def test_refuses_a_bad_version(self) -> None:
        with pytest.raises(ExtensionError, match="not a valid extension version"):
            ExtensionFetcher.check("a.b", "../1")


class _Response:
    def __init__(self, body: bytes) -> None:
        self._io = io.BytesIO(body)

    def read1(self, size: int = -1) -> bytes:
        return self._io.read(size)

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_: object) -> None:
        return None


class _Opener:
    def __init__(self, outcome: Any) -> None:
        self.outcome = outcome
        self.requests: list[Any] = []

    def open(self, request: Any, timeout: int) -> Any:
        self.requests.append(request)
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return _Response(self.outcome)


class TestGet:
    def use(self, monkeypatch: pytest.MonkeyPatch, outcome: Any) -> _Opener:
        opener = _Opener(outcome)
        monkeypatch.setattr(ExtensionFetcher, "_opener", opener)
        return opener

    def test_reads_the_body(self, monkeypatch: pytest.MonkeyPatch) -> None:
        opener = self.use(monkeypatch, b"hello")
        got = ExtensionFetcher._get("https://x.test/a", headers={"X-A": "1"}, limit=100)
        assert got == b"hello"
        assert opener.requests[0].get_header("X-a") == "1"

    def test_refuses_plain_http(self) -> None:
        with pytest.raises(ExtensionError, match="non-HTTPS"):
            ExtensionFetcher._get("http://x.test/a", limit=10)

    def test_a_body_over_the_limit_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.use(monkeypatch, b"x" * 50)
        with pytest.raises(ExtensionError, match="larger than 0 MB"):
            ExtensionFetcher._get("https://x.test/a", limit=10)

    def test_404_names_the_missing_extension(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.use(monkeypatch, urllib.error.HTTPError("https://x", 404, "no", {}, None))  # type: ignore[arg-type]
        with pytest.raises(ExtensionError, match="no such extension or version"):
            ExtensionFetcher._get("https://x.test/a", limit=10)

    def test_other_status_is_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.use(monkeypatch, urllib.error.HTTPError("https://x", 503, "no", {}, None))  # type: ignore[arg-type]
        with pytest.raises(ExtensionError, match="HTTP 503"):
            ExtensionFetcher._get("https://x.test/a", limit=10)

    def test_unreachable_registry(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.use(monkeypatch, urllib.error.URLError("down"))
        with pytest.raises(ExtensionError, match="could not reach the registry"):
            ExtensionFetcher._get("https://x.test/a", limit=10)


class TestRedirects:
    def redirect(self, url: str) -> Any:
        handler = extensions._NoRedirect()
        req = urllib.request.Request("https://open-vsx.org/a")
        return handler.redirect_request(req, io.BytesIO(), 302, "Found", {}, url)

    def test_https_redirect_is_followed(self) -> None:
        assert self.redirect("https://cdn.test/b").full_url == "https://cdn.test/b"

    def test_redirect_to_http_is_refused(self) -> None:
        with pytest.raises(ExtensionError, match="non-HTTPS"):
            self.redirect("http://cdn.test/b")


class TestOpenVsx:
    base = f"{extensions.OPEN_VSX}/pub/name/latest"

    def test_a_matching_digest_saves_the_package(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        serve(
            monkeypatch,
            {
                self.base: vsx_meta(
                    download="https://d.test/p.vsix", sha256="https://d.test/p.sha"
                ),
                "https://d.test/p.sha": f"{DIGEST.upper()}  p.vsix\n".encode(),
                "https://d.test/p.vsix": VSIX,
            },
        )
        got = ExtensionFetcher.open_vsx("pub.name", None, tmp_path)
        assert got.path == tmp_path / "pub.name-1.2.3.vsix"
        assert got.path.read_bytes() == VSIX
        assert (got.registry, got.version) == ("open-vsx", "1.2.3")
        assert got.integrity == f"sha256:{DIGEST} (matches Open VSX)"

    def test_a_digest_mismatch_is_refused_and_nothing_is_written(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        serve(
            monkeypatch,
            {
                self.base: vsx_meta(
                    download="https://d.test/p.vsix", sha256="https://d.test/p.sha"
                ),
                "https://d.test/p.sha": b"0" * 64,
                "https://d.test/p.vsix": VSIX,
            },
        )
        with pytest.raises(ExtensionError, match="does not match Open VSX"):
            ExtensionFetcher.open_vsx("pub.name", None, tmp_path)
        assert list(tmp_path.iterdir()) == []

    def test_a_digest_file_that_is_not_a_digest_is_refused(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        serve(
            monkeypatch,
            {
                self.base: vsx_meta(
                    download="https://d.test/p.vsix", sha256="https://d.test/p.sha"
                ),
                "https://d.test/p.sha": b"not a digest",
            },
        )
        with pytest.raises(ExtensionError, match="does not hold a SHA-256"):
            ExtensionFetcher.open_vsx("pub.name", None, tmp_path)

    def test_a_release_without_download_or_digest_is_refused(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        serve(monkeypatch, {self.base: vsx_meta(download="https://d.test/p.vsix")})
        with pytest.raises(ExtensionError, match="no download and digest"):
            ExtensionFetcher.open_vsx("pub.name", None, tmp_path)

    def test_metadata_that_is_not_json_is_refused(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        serve(monkeypatch, {self.base: b"<html>"})
        with pytest.raises(ExtensionError, match="not JSON"):
            ExtensionFetcher.open_vsx("pub.name", None, tmp_path)

    def test_a_download_that_is_not_a_zip_is_refused(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        body = b"MZ not a zip"
        serve(
            monkeypatch,
            {
                f"{extensions.OPEN_VSX}/pub/name/2.0.0": vsx_meta(
                    download="https://d.test/p.vsix", sha256="https://d.test/p.sha"
                ),
                "https://d.test/p.sha": hashlib.sha256(body).hexdigest().encode(),
                "https://d.test/p.vsix": body,
            },
        )
        with pytest.raises(ExtensionError, match="not a VSIX"):
            ExtensionFetcher.open_vsx("pub.name", "2.0.0", tmp_path)


class _Kit_gallery:
    @staticmethod
    def gallery(versions: list[dict[str, Any]] | None, *, empty: bool = False) -> bytes:
        exts = [] if empty else [{"versions": versions}]
        return json.dumps({"results": [{"extensions": exts}]}).encode()


gallery = _Kit_gallery.gallery


PACKAGE_FILE = {
    "assetType": "Microsoft.VisualStudio.Services.VSIXPackage",
    "source": "https://m.test/p",
}


class TestMarketplace:
    def test_picks_the_platform_independent_version(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        versions = [
            {"version": "1.0.0", "targetPlatform": "win32-x64", "files": [PACKAGE_FILE]},
            {"version": "1.0.0", "targetPlatform": "universal", "files": [PACKAGE_FILE]},
        ]
        asked = serve(
            monkeypatch,
            {extensions.GALLERY: gallery(versions), "https://m.test/p": VSIX},
        )
        got = ExtensionFetcher.marketplace("pub.name", "1.0.0", tmp_path)
        assert got.registry == "vscode-marketplace"
        assert got.integrity.startswith(f"sha256:{DIGEST} (TLS only")
        assert got.path.read_bytes() == VSIX
        assert asked == [extensions.GALLERY, "https://m.test/p"]

    @pytest.mark.parametrize(
        ("body", "message"),
        [
            (b"not json", "in a form this does not read"),
            (b'{"results": []}', "in a form this does not read"),
            (gallery(None, empty=True), "no such extension"),
            (gallery([{"version": "9", "files": []}]), "no platform-independent package"),
            (gallery([{"version": "1.0.0", "files": []}]), "lists no package file"),
        ],
    )
    def test_refusals(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, body: bytes, message: str
    ) -> None:
        serve(monkeypatch, {extensions.GALLERY: body})
        with pytest.raises(ExtensionError, match=message):
            ExtensionFetcher.marketplace("pub.name", "1.0.0", tmp_path)
