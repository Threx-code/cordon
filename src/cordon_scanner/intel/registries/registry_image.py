"""An image pulled from its registry, written as an OCI layout for the image reader to scan.

`cordon-scanner scan pkg:docker/nginx@1.27 --online` asks the registry, the way `docker pull`
does, through the OCI distribution API:

    GET /v2/<repository>/manifests/<tag or digest>     the manifest, or the image index
    GET /v2/<repository>/blobs/<digest>                each configuration and each layer

and writes what it fetched as an OCI layout (index.json and blobs/sha256/...), which the image
reader opens as it opens `docker save` output -- every platform of a multi-platform image
included, as long as they fit the budget.

Trust is the digest's, not the transport's: every blob is checked against the sha256 its
descriptor names before it is written, and a manifest fetched by digest against that digest. A
public image needs no account: the anonymous bearer token Docker Hub and GHCR issue for `pull` is
asked for when the registry answers 401. One that wants credentials is refused with the way round
it (save the image, scan the archive): nothing here holds a registry password. The token goes only
to the registry; a blob download redirected to a CDN goes there without it.

HTTPS only, except to a registry on this machine (localhost), as Docker itself allows.
"""

from __future__ import annotations

import hashlib
import http.client
import io
import json
import re
import tarfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import IO, Any, Final

MEDIA_INDEX: Final = (
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
)
MEDIA_MANIFEST: Final = (
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
)
ACCEPT: Final = ", ".join((*MEDIA_INDEX, *MEDIA_MANIFEST))
HUB: Final = "registry-1.docker.io"
LOCAL_HOSTS: Final = frozenset({"localhost", "127.0.0.1", "[::1]"})
TIMEOUT: Final = 30.0
MAX_MANIFEST: Final = 4 << 20
MAX_BYTES: Final = 2 << 30
"""Everything one pull may download, every platform together."""
CHUNK: Final = 1 << 20


class RegistryImageError(ValueError):
    """Why an image could not be pulled, worded for the person who asked."""


@dataclass
class Pull:
    """What has been fetched so far, by digest."""

    blobs: dict[str, bytes] = field(default_factory=dict)
    downloaded: int = 0
    platforms: list[str] = field(default_factory=list)
    skipped_platforms: list[str] = field(default_factory=list)


class _AuthOnlyToRegistry(urllib.request.HTTPRedirectHandler):
    """Follow a blob's redirect (to a CDN) without the registry's token."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            new.remove_header("Authorization")
            target = urllib.parse.urlsplit(newurl)
            # HTTPS, or a host on this machine (a registry under test), and nothing else.
            if target.scheme != "https" and target.hostname not in (
                "localhost",
                "127.0.0.1",
                "::1",
            ):
                return None
        return new


class RegistryImage:
    def __init__(self, registry: str | None, repository: str) -> None:
        self.host = registry or HUB
        self.repository = repository
        bare = (
            self.host.split(":")[0]
            if not self.host.startswith("[")
            else self.host.split("]")[0] + "]"
        )
        self.scheme = "http" if bare in LOCAL_HOSTS else "https"
        self.token: str | None = None
        self.opener = urllib.request.build_opener(_AuthOnlyToRegistry)

    # -- HTTP ----------------------------------------------------------------------------

    def _url(self, kind: str, reference: str) -> str:
        return f"{self.scheme}://{self.host}/v2/{self.repository}/{kind}/{reference}"

    def _open(self, url: str, accept: str | None = None) -> Any:
        for attempt in range(2):
            request = urllib.request.Request(url)  # noqa: S310 - https, or a registry on localhost
            request.add_header("User-Agent", "cordon-scanner")
            if accept:
                request.add_header("Accept", accept)
            if self.token:
                request.add_header("Authorization", f"Bearer {self.token}")
            try:
                return self.opener.open(request, timeout=TIMEOUT)
            except urllib.error.HTTPError as exc:
                exc.close()
                if exc.code == 401 and attempt == 0 and self._authenticate(exc.headers):
                    continue
                if exc.code in (401, 403):
                    raise RegistryImageError(
                        f"{self.host} requires signing in to pull {self.repository}; pull it with "
                        "your own credentials, `docker save` it, and scan the archive"
                    ) from exc
                if exc.code == 404:
                    raise RegistryImageError(
                        f"{self.host} has no {url.rsplit('/', 3)[-3:]}"
                    ) from exc
                raise RegistryImageError(f"{self.host} answered HTTP {exc.code}") from exc
            except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
                raise RegistryImageError(
                    f"{self.host} could not be reached ({type(exc).__name__})"
                ) from exc
        raise RegistryImageError(f"{self.host} refused the anonymous token it issued")

    def _authenticate(self, headers: Any) -> bool:
        """The anonymous `pull` token a public registry issues on a 401's challenge."""
        challenge = str(headers.get("WWW-Authenticate", ""))
        if not challenge.lower().startswith("bearer "):
            return False
        fields = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
        realm = fields.get("realm", "")
        if urllib.parse.urlsplit(realm).scheme != "https":
            return False
        query = {
            k: v
            for k, v in (("service", fields.get("service")), ("scope", fields.get("scope")))
            if v
        }
        if "scope" not in query:
            query["scope"] = f"repository:{self.repository}:pull"
        url = f"{realm}?{urllib.parse.urlencode(query)}"
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "cordon-scanner"})  # noqa: S310
            with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310
                body = json.loads(response.read(1 << 20))
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError):
            return False
        token = body.get("token") or body.get("access_token")
        self.token = str(token) if token else None
        return self.token is not None

    # -- Fetching ------------------------------------------------------------------------

    def manifest(self, reference: str) -> tuple[bytes, str]:
        with self._open(self._url("manifests", reference), ACCEPT) as response:
            body = response.read(MAX_MANIFEST + 1)
            media = str(response.headers.get("Content-Type", "")).split(";")[0].strip()
        if len(body) > MAX_MANIFEST:
            raise RegistryImageError("a manifest larger than any real one was served")
        if reference.startswith("sha256:") and hashlib.sha256(body).hexdigest() != reference[7:]:
            raise RegistryImageError(
                f"the manifest served for {reference[:19]}... is not that manifest"
            )
        try:
            document = json.loads(body)
        except ValueError as exc:
            raise RegistryImageError("the registry served a manifest that is not JSON") from exc
        return body, str(document.get("mediaType") or media)

    def blob(self, digest: str, pull: Pull) -> bytes:
        if digest in pull.blobs:
            return pull.blobs[digest]
        algorithm, _, expected = digest.partition(":")
        if algorithm != "sha256" or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise RegistryImageError(f"a blob named by an unsupported digest: {digest[:24]}")
        hasher = hashlib.sha256()
        buffer = io.BytesIO()
        with self._open(self._url("blobs", digest)) as response:
            while chunk := response.read(CHUNK):
                pull.downloaded += len(chunk)
                if pull.downloaded > MAX_BYTES:
                    raise RegistryImageError(
                        f"the image is larger than the {MAX_BYTES >> 30} GiB a pull may download"
                    )
                hasher.update(chunk)
                buffer.write(chunk)
        if hasher.hexdigest() != expected:
            raise RegistryImageError(f"a layer's bytes do not match its digest ({digest[:19]}...)")
        data = buffer.getvalue()
        pull.blobs[digest] = data
        return data

    def image(self, manifest_body: bytes, pull: Pull) -> None:
        document = json.loads(manifest_body)
        for descriptor in (document.get("config") or {}, *(document.get("layers") or ())):
            digest = str(descriptor.get("digest", ""))
            if digest:
                self.blob(digest, pull)

    def pull(self, reference: str) -> tuple[bytes, Pull]:
        """The OCI layout of the image `reference` (a tag or a digest) names, as tar bytes."""
        pull = Pull()
        body, media = self.manifest(reference)
        top_digest = f"sha256:{hashlib.sha256(body).hexdigest()}"
        pull.blobs[top_digest] = body
        if media in MEDIA_INDEX or "manifests" in json.loads(body):
            index = json.loads(body)
            kept = []
            for descriptor in index.get("manifests") or ():
                platform = descriptor.get("platform") or {}
                label = "/".join(
                    str(platform[k]) for k in ("os", "architecture", "variant") if platform.get(k)
                )
                if label.startswith("unknown"):
                    continue  # an attestation manifest, not a platform
                try:
                    child, _media = self.manifest(str(descriptor.get("digest", "")))
                    pull.blobs[str(descriptor["digest"])] = child
                    self.image(child, pull)
                except RegistryImageError as exc:
                    if "larger than" not in str(exc) or not pull.platforms:
                        raise
                    pull.skipped_platforms.append(label or "?")
                    continue
                pull.platforms.append(label)
                kept.append(descriptor)
            if pull.skipped_platforms:
                # What was not fetched is not in the layout: the index written lists what was.
                index = {**index, "manifests": kept}
                body = json.dumps(index).encode()
                top_digest = f"sha256:{hashlib.sha256(body).hexdigest()}"
                pull.blobs[top_digest] = body
        else:
            self.image(body, pull)
        layout = {"schemaVersion": 2, "manifests": [{"digest": top_digest, "mediaType": media}]}
        return RegistryImage.write_layout(layout, pull.blobs), pull

    @staticmethod
    def write_layout(index: dict[str, Any], blobs: dict[str, bytes]) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            RegistryImage._add(archive, "oci-layout", b'{"imageLayoutVersion":"1.0.0"}')
            RegistryImage._add(archive, "index.json", json.dumps(index).encode())
            for digest, data in blobs.items():
                RegistryImage._add(archive, f"blobs/sha256/{digest.partition(':')[2]}", data)
        return buffer.getvalue()

    @staticmethod
    def _add(archive: tarfile.TarFile, name: str, data: bytes) -> None:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        handle: IO[bytes] = io.BytesIO(data)
        archive.addfile(info, handle)


__all__ = ["Pull", "RegistryImage", "RegistryImageError"]
