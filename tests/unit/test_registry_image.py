"""Pulling an image from its registry (`intel/registry_image`), against a registry on localhost.

The registry here speaks the OCI distribution API as Docker Hub does: a 401 with a bearer
challenge, an anonymous token, an image index with an attestation manifest beside the platforms,
and blob downloads redirected to another host. Checked against Docker Hub itself when this was
written: alpine:3.20, eight platforms, 28 MB, every blob verified.
"""

from __future__ import annotations

import hashlib
import http.server
import json
import threading

import pytest

from cordon_scanner.images.oci import ImageLayers
from cordon_scanner.intel import registry_image
from cordon_scanner.intel.registry_image import RegistryImage, RegistryImageError
from imagekit import ImageKit


class Digest:
    @staticmethod
    def of(data: bytes) -> str:
        return f"sha256:{hashlib.sha256(data).hexdigest()}"


class FakeRegistry:
    """A registry and its token service and CDN, in one server on 127.0.0.1."""

    def __init__(self, *, anonymous: bool = True, corrupt: bool = False) -> None:
        self.blobs: dict[str, bytes] = {}
        self.manifests: dict[str, bytes] = {}
        self.cdn_saw_token: list[bool] = []
        self.anonymous = anonymous
        self.corrupt = corrupt
        status = "\n".join(
            [ImageKit.dpkg_stanza("libc6", "2.36-9"), ImageKit.dpkg_stanza("bash", "5.2.15-2")]
        )
        layer = ImageKit.layer(
            {
                "etc/os-release": b'ID=debian\nVERSION_ID="12"\n',
                "var/lib/dpkg/status": status.encode(),
            }
        )
        config = b'{"architecture": "amd64", "os": "linux"}'
        self.blobs[Digest.of(layer)] = layer
        self.blobs[Digest.of(config)] = config
        image = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {"digest": Digest.of(config)},
                "layers": [{"digest": Digest.of(layer)}],
            }
        ).encode()
        attestation = json.dumps({"schemaVersion": 2, "layers": []}).encode()
        self.manifests[Digest.of(image)] = image
        self.manifests[Digest.of(attestation)] = attestation
        index = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {
                        "digest": Digest.of(image),
                        "platform": {"os": "linux", "architecture": "amd64"},
                    },
                    {
                        "digest": Digest.of(attestation),
                        "platform": {"os": "unknown", "architecture": "unknown"},
                    },
                ],
            }
        ).encode()
        self.manifests["1.0"] = index
        self.manifests[Digest.of(index)] = index

    def serve(self) -> tuple[http.server.HTTPServer, str]:
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args) -> None:
                pass

            def send(self, code: int, body: bytes = b"", headers: dict | None = None) -> None:
                self.send_response(code)
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                host = self.headers.get("Host", "")
                if self.path.startswith("/cdn/"):
                    fake.cdn_saw_token.append("Authorization" in self.headers)
                    data = fake.blobs[self.path.removeprefix("/cdn/")]
                    return self.send(200, b"x" + data[1:] if fake.corrupt else data)
                if self.path.startswith("/token"):
                    return self.send(200, json.dumps({"token": "anon-pull"}).encode())
                if self.headers.get("Authorization") != "Bearer anon-pull":
                    realm = f"http://{host}/token" if fake.anonymous else ""
                    challenge = (
                        f'Bearer realm="{realm}",service="fake",scope="repository:team/app:pull"'
                    )
                    return self.send(401, b"", {"WWW-Authenticate": challenge})
                _, _, _repo1, _repo2, kind, reference = self.path.split("/", 5)
                if kind == "manifests":
                    return self.send(
                        200, fake.manifests[reference], {"Content-Type": "application/json"}
                    )
                # A blob is served from somewhere else, as Docker Hub serves from its CDN.
                return self.send(307, b"", {"Location": f"http://{host}/cdn/{reference}"})

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server, f"localhost:{server.server_address[1]}"


class RegistryFixture:
    """A fake registry per test, shut down and closed after it."""

    @pytest.fixture
    def registry(self, monkeypatch):
        servers = []

        def start(**options):
            fake = FakeRegistry(**options)
            server, host = fake.serve()
            servers.append(server)
            return fake, host

        # The token service of this fake is http on localhost; a real one is https, which the code
        # requires of any realm. Allowed here for the fake only.
        original = registry_image.urllib.parse.urlsplit

        def realm_allowing_localhost(url, *args, **kwargs):
            parts = original(url, *args, **kwargs)
            if parts.hostname == "localhost" and parts.path == "/token":
                return parts._replace(scheme="https")
            return parts

        monkeypatch.setattr(registry_image.urllib.parse, "urlsplit", realm_allowing_localhost)
        yield start
        for server in servers:
            server.shutdown()
            server.server_close()


class TestPull(RegistryFixture):
    def test_a_public_image_with_an_anonymous_token(self, registry) -> None:
        _, host = registry()
        data, pull = RegistryImage(host, "team/app").pull("1.0")
        assert pull.platforms == ["linux/amd64"]  # the attestation manifest is not a platform
        inventory = ImageLayers.read_image(data)
        assert {p.name for p in inventory.packages} == {"libc6", "bash"}

    def test_the_token_never_reaches_the_cdn(self, registry) -> None:
        fake, host = registry()
        RegistryImage(host, "team/app").pull("1.0")
        assert fake.cdn_saw_token and not any(fake.cdn_saw_token)

    def test_a_blob_that_is_not_its_digest_is_refused(self, registry) -> None:
        _, host = registry(corrupt=True)
        with pytest.raises(RegistryImageError, match="do not match its digest"):
            RegistryImage(host, "team/app").pull("1.0")

    def test_a_registry_that_wants_credentials_says_how_to_scan_instead(self, registry) -> None:
        _, host = registry(anonymous=False)
        with pytest.raises(RegistryImageError, match="docker save"):
            RegistryImage(host, "team/app").pull("1.0")

    def test_only_https_except_on_this_machine(self) -> None:
        assert RegistryImage("ghcr.io", "acme/app").scheme == "https"
        assert RegistryImage(None, "library/alpine").host == "registry-1.docker.io"
        assert RegistryImage("localhost:5000", "team/app").scheme == "http"


class TestTheTarget:
    @pytest.mark.conformance("image", "image.registry")
    def test_a_package_url_names_an_image_on_any_registry(self) -> None:
        from cordon_scanner.sources.package import PackageTarget

        assert PackageTarget.parse("pkg:docker/alpine@3.20").name == "library/alpine"
        target = PackageTarget.parse("pkg:docker/ghcr.io/acme/app@sha256:" + "a" * 64)
        assert (target.name, target.version) == ("ghcr.io/acme/app", "sha256:" + "a" * 64)
        assert PackageTarget.parse("pkg:oci/library/nginx").version == "latest"
