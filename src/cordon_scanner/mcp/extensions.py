"""An IDE extension, fetched by its identifier so it can be scanned before it is installed.

Two registries. Open VSX (what Cursor, Windsurf, VSCodium and Gitpod install from) publishes a
SHA-256 digest beside every package, and the download is refused unless it matches. The Visual
Studio Marketplace publishes no digest -- only a signature that needs Microsoft's signing tool to
check -- so a Marketplace download is reported as verified by TLS alone, which is what it is.

The package is written into a private temporary directory, scanned, and removed with it. Nothing is
installed or unpacked to disk by this module; the scanner opens the archive itself.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

MAX_VSIX: Final = 200 << 20
OPEN_VSX: Final = "https://open-vsx.org/api"
GALLERY: Final = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery"
_ID: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,127}\.[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_VERSION: Final = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$")
_UA: Final = {"User-Agent": "cordon-scanner-mcp"}


class ExtensionError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class Fetched:
    path: Path
    identifier: str
    version: str
    registry: str
    integrity: str


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Follows a redirect only to HTTPS: a download must not be steered to plain HTTP."""

    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> Any:
        if not newurl.startswith("https://"):
            raise ExtensionError(f"refused a redirect to a non-HTTPS address: {newurl[:80]}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class ExtensionFetcher:
    _opener = urllib.request.build_opener(_NoRedirect)

    @staticmethod
    def check(identifier: str, version: str | None) -> tuple[str, str]:
        if not _ID.match(identifier):
            raise ExtensionError(f"an extension is named publisher.name, not {identifier[:80]!r}")
        if version is not None and not _VERSION.match(version):
            raise ExtensionError(f"not a valid extension version: {version[:40]!r}")
        publisher, _, name = identifier.partition(".")
        return publisher, name

    @classmethod
    def _get(
        cls,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        limit: int,
    ) -> bytes:
        if not url.startswith("https://"):
            raise ExtensionError(f"refused a non-HTTPS address: {url[:80]}")
        request = urllib.request.Request(url, data=data, headers={**_UA, **(headers or {})})  # noqa: S310 - https checked above
        try:
            with cls._opener.open(request, timeout=120) as response:
                body: bytes = response.read(limit + 1)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise ExtensionError("the registry has no such extension or version") from exc
            raise ExtensionError(f"the registry answered HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ExtensionError(f"could not reach the registry: {exc}") from exc
        if len(body) > limit:
            raise ExtensionError(f"the download is larger than {limit >> 20} MB")
        return body

    @classmethod
    def open_vsx(cls, identifier: str, version: str | None, into: Path) -> Fetched:
        publisher, name = cls.check(identifier, version)
        meta_url = f"{OPEN_VSX}/{urllib.parse.quote(publisher)}/{urllib.parse.quote(name)}/{urllib.parse.quote(version or 'latest')}"
        try:
            meta = json.loads(cls._get(meta_url, limit=8 << 20))
        except ValueError as exc:
            raise ExtensionError("Open VSX answered with something that is not JSON") from exc
        files = meta.get("files") or {}
        download, digest_url = files.get("download"), files.get("sha256")
        if not download or not digest_url:
            raise ExtensionError("Open VSX lists no download and digest for this release")
        expected = (
            cls._get(str(digest_url), limit=4096)
            .decode("ascii", "replace")
            .strip()
            .split()[0]
            .lower()
        )
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ExtensionError("Open VSX's digest file does not hold a SHA-256 digest")
        body = cls._get(str(download), limit=MAX_VSIX)
        actual = hashlib.sha256(body).hexdigest()
        if actual != expected:
            raise ExtensionError(
                f"the download's SHA-256 {actual} does not match Open VSX's {expected}; refused"
            )
        resolved = str(meta.get("version") or version or "")
        return cls._save(
            into, identifier, resolved, "open-vsx", f"sha256:{actual} (matches Open VSX)", body
        )

    @classmethod
    def marketplace(cls, identifier: str, version: str | None, into: Path) -> Fetched:
        cls.check(identifier, version)
        query = json.dumps(
            {
                "filters": [
                    {
                        "criteria": [{"filterType": 7, "value": identifier}],
                        "pageNumber": 1,
                        "pageSize": 1,
                    }
                ],
                # IncludeVersions | IncludeFiles | IncludeAssetUri
                "flags": 0x1 | 0x2 | 0x80,
            }
        ).encode()
        try:
            reply = json.loads(
                cls._get(
                    GALLERY,
                    data=query,
                    headers={
                        "Accept": "application/json;api-version=7.2-preview.1",
                        "Content-Type": "application/json",
                    },
                    limit=32 << 20,
                )
            )
            extensions = reply["results"][0]["extensions"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise ExtensionError("the Marketplace answered in a form this does not read") from exc
        if not extensions:
            raise ExtensionError("the Marketplace has no such extension")
        chosen = None
        for entry in extensions[0].get("versions") or []:
            platform = entry.get("targetPlatform")
            if (version is None or entry.get("version") == version) and platform in (
                None,
                "",
                "universal",
            ):
                chosen = entry
                break
        if chosen is None:
            raise ExtensionError(
                "the Marketplace has no platform-independent package for that version"
            )
        source = next(
            (
                f.get("source")
                for f in chosen.get("files") or []
                if f.get("assetType") == "Microsoft.VisualStudio.Services.VSIXPackage"
            ),
            None,
        )
        if not source:
            raise ExtensionError("the Marketplace lists no package file for that version")
        body = cls._get(str(source), limit=MAX_VSIX)
        return cls._save(
            into,
            identifier,
            str(chosen.get("version")),
            "vscode-marketplace",
            f"sha256:{hashlib.sha256(body).hexdigest()} (TLS only: the Marketplace publishes no digest to compare)",
            body,
        )

    @staticmethod
    def _save(
        into: Path, identifier: str, version: str, registry: str, integrity: str, body: bytes
    ) -> Fetched:
        if body[:2] != b"PK":
            raise ExtensionError("the download is not a VSIX (zip) package")
        path = into / f"{identifier}-{re.sub(r'[^0-9A-Za-z.+-]', '_', version)}.vsix"
        path.write_bytes(body)
        return Fetched(path, identifier, version, registry, integrity)
