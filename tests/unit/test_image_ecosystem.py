"""Container images: references, Dockerfiles, Compose files, an image's own identity and the graph
of its operating-system packages."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile

import pytest
from tests.imagekit import ImageKit

from cordon_scanner.core.content import FileContent
from cordon_scanner.core.models import Dependency, Scope
from cordon_scanner.ecosystems.image import (
    Compose,
    Dockerfile,
    ImageEcosystem,
    ImageReference,
    Interpolation,
)
from cordon_scanner.images.oci import ImageIdentity, ImageLayers
from cordon_scanner.images.packages import OsPackage, PackageDatabases, PackageGraph


class ImageHelpers:
    """Helpers for test_image_ecosystem.py."""

    @staticmethod
    def dockerfile(text: str):
        return Dockerfile.parse(FileContent.from_bytes("Dockerfile", text.encode()), "image")

    @staticmethod
    def compose(text: str, environment: dict[str, str] | None = None):
        return Compose.parse(
            FileContent.from_bytes("compose.yaml", text.encode()), "image", environment or {}
        )

    @staticmethod
    def by_name(manifest) -> dict[str, list]:
        out: dict[str, list] = {}
        for declared in manifest.dependencies:
            out.setdefault(declared.name, []).append(declared)
        return out


class TestReferences:
    @pytest.mark.conformance("image", "UNI-04")
    @pytest.mark.parametrize(
        ("written", "familiar", "registry", "repository", "tag", "digest"),
        [
            ("python", "python", None, "library/python", None, None),
            ("python:3.12-slim", "python", None, "library/python", "3.12-slim", None),
            ("docker.io/library/python:3.12", "python", None, "library/python", "3.12", None),
            (
                "index.docker.io/bitnami/redis:7.2",
                "bitnami/redis",
                None,
                "bitnami/redis",
                "7.2",
                None,
            ),
            (
                "ghcr.io/acme/app:1.0@sha256:" + "a" * 64,
                "ghcr.io/acme/app",
                "ghcr.io",
                "acme/app",
                "1.0",
                "sha256:" + "a" * 64,
            ),
            (
                "localhost:5000/team/tool",
                "localhost:5000/team/tool",
                "localhost:5000",
                "team/tool",
                None,
                None,
            ),
            (
                "registry.example.internal:8443/a/b/c:v2",
                "registry.example.internal:8443/a/b/c",
                "registry.example.internal:8443",
                "a/b/c",
                "v2",
                None,
            ),
        ],
    )
    def test_references_read_as_the_docker_client_reads_them(
        self, written, familiar, registry, repository, tag, digest
    ) -> None:
        reference = ImageReference.parse(written)
        assert reference is not None
        assert (
            reference.familiar,
            reference.registry,
            reference.repository,
            reference.tag,
            reference.digest,
        ) == (familiar, registry, repository, tag, digest)

    @pytest.mark.conformance("image", "UNI-03")
    @pytest.mark.parametrize(
        "written",
        ["Python:3", "python:", "ghcr.io/", "a b", "alpine@sha256:xyz", "../etc/passwd", "x" * 600],
    )
    def test_what_the_client_refuses_is_refused(self, written) -> None:
        assert ImageReference.parse(written) is None

    def test_a_declaration_keeps_the_spelling_written(self) -> None:
        declared = ImageReference.declare(
            "docker.io/library/python:3.12@sha256:" + "b" * 64,
            scope=Scope.RUNTIME,
            field_name="FROM",
        )
        assert declared is not None
        assert (
            declared.name,
            declared.alias,
            declared.spec,
            declared.integrity,
            declared.source,
        ) == (
            "python",
            "docker.io/library/python",
            "3.12",
            "sha256:" + "b" * 64,
            None,
        )
        assert (
            ImageReference.declare(
                "ghcr.io/acme/app", scope=Scope.RUNTIME, field_name="FROM"
            ).source
            == "registry:ghcr.io"
        )

    def test_interpolation(self) -> None:
        values = {"TAG": "1.0", "EMPTY": ""}
        assert Interpolation.expand("app:${TAG}", values) == ("app:1.0", ())
        assert Interpolation.expand("app:${MISSING:-2.0}", values) == ("app:2.0", ())
        assert Interpolation.expand("app:${EMPTY:-3.0}-${EMPTY-x}", values) == ("app:3.0-", ())
        assert Interpolation.expand("app:${TAG:+set}", values) == ("app:set", ())
        assert Interpolation.expand("app:$MISSING", values) == ("app:$MISSING", ("MISSING",))
        assert Interpolation.expand("cost $$5", values) == ("cost $5", ())


class TestDockerfiles:
    @pytest.mark.conformance("image", "image.multi-stage", "UNI-08")
    def test_stages_runtime_and_build_images(self) -> None:
        manifest = ImageHelpers.dockerfile(
            "ARG GO=1.23\n"
            "FROM --platform=$BUILDPLATFORM golang:${GO}-alpine AS build\n"
            "RUN go build ./...\n"
            "FROM node:20 AS assets\n"
            "FROM build AS test\n"
            "FROM gcr.io/distroless/static:nonroot@sha256:" + "c" * 64 + "\n"
            "COPY --from=build /out/app /app\n"
            "COPY --from=nginx:1.27 /etc/nginx/mime.types /etc/\n"
            "COPY --from=1 /dist /dist\n"
            "RUN --mount=type=bind,from=busybox:1.36,target=/bb true\n"
        )
        assert manifest.parse_error is None
        found = ImageHelpers.by_name(manifest)
        assert found["golang"][0].spec == "1.23-alpine" and found["golang"][0].scope is Scope.BUILD
        assert found["golang"][0].platform == ("platform $BUILDPLATFORM",)
        assert found["node"][0].scope is Scope.BUILD
        runtime = found["gcr.io/distroless/static"][0]
        assert runtime.scope is Scope.RUNTIME and runtime.integrity == "sha256:" + "c" * 64
        assert found["nginx"][0].scope is Scope.BUILD and found["busybox"][0].spec == "1.36"
        # `build`, `test` and `1` are stages, not images.
        assert set(found) == {"golang", "node", "gcr.io/distroless/static", "nginx", "busybox"}
        assert [hook.command for hook in manifest.hooks] == ["go build ./...", "true"]

    def test_the_runtime_image_follows_stages_down(self) -> None:
        found = ImageHelpers.by_name(
            ImageHelpers.dockerfile("FROM python:3.12 AS base\nFROM base AS deps\nFROM deps\n")
        )
        assert found["python"][0].scope is Scope.RUNTIME

    @pytest.mark.conformance("image", "UNI-02")
    def test_escape_directive_continuations_heredocs_and_a_byte_order_mark(self) -> None:
        manifest = ImageHelpers.dockerfile(
            "﻿# escape=`\n"
            "FROM mcr.microsoft.com/windows/servercore:ltsc2022 AS win\n"
            "RUN powershell -Command `\n"
            "    # a comment inside the continuation\n"
            "    Write-Host hi\n"
            "RUN <<EOF\n"
            "FROM not-an-instruction\n"
            "EOF\n"
            "COPY <<-CONF /etc/app.conf\n"
            "\tkey=value\n"
            "\tCONF\n"
        )
        assert manifest.parse_error is None
        assert [d.name for d in manifest.dependencies] == ["mcr.microsoft.com/windows/servercore"]
        assert manifest.hooks[0].command == "powershell -Command Write-Host hi"

    @pytest.mark.conformance("image", "UNI-03")
    @pytest.mark.parametrize(
        ("text", "error"),
        [
            ("RUN true\n", "without FROM"),
            ("LABEL a=b\nFROM alpine\n", "before the first FROM"),
            ("FROM alpine\nFRMO x\n", "unknown instruction FRMO"),
            ("FROM alpine\nRUN a \\\n", "ends inside a continued instruction"),
            ("FROM alpine\nRUN <<EOF\necho\n", "never closed"),
            ("FROM Alpine:3\n", "not an image reference"),
            ("FROM alpine AS\n", "FROM takes an image"),
        ],
    )
    def test_what_a_build_would_stop_on_is_a_diagnostic(self, text, error) -> None:
        manifest = ImageHelpers.dockerfile(text)
        assert manifest.parse_error and error in manifest.parse_error

    def test_an_image_from_a_build_argument_with_no_default_is_said(self) -> None:
        manifest = ImageHelpers.dockerfile("ARG BASE\nFROM ${BASE}\nRUN true\n")
        assert manifest.dependencies == ()
        assert "the build argument BASE, which has no default" in manifest.sources[0]


class TestComposeFiles:
    @pytest.mark.conformance("image", "UNI-02", "UNI-04")
    def test_services_anchors_environment_profiles_and_builds(self) -> None:
        manifest = ImageHelpers.compose(
            "x-base: &base\n"
            '  image: "redis:${REDIS:-7.2}"\n'
            "  restart: always\n"
            "services:\n"
            "  cache:\n"
            "    <<: *base\n"
            "  cache-replica:\n"
            "    <<: [*base]\n"
            "    image: redis:7.4 # its own wins\n"
            "  web:\n"
            "    build:\n"
            "      context: ./web\n"
            "      additional_contexts:\n"
            "        - base=docker-image://python:3.12-slim\n"
            "    image: acme/web:${TAG}\n"
            "  tools:\n"
            "    image: ${REGISTRY}/tools:1.0\n"
            "    profiles: [debug, ops]\n"
            "    platform: linux/arm64\n"
            "  worker:\n"
            "    extends:\n"
            "      service: web\n",
            {"REGISTRY": "ghcr.io/acme"},
        )
        assert manifest.parse_error is None
        found = ImageHelpers.by_name(manifest)
        assert [d.spec for d in found["redis"]] == ["7.2", "7.4"]
        assert found["python"][0].scope is Scope.BUILD
        assert found["ghcr.io/acme/tools"][0].platform == (
            "profile debug",
            "profile ops",
            "platform linux/arm64",
        )
        # What `web` builds and tags is its output, not a pull.
        assert "acme/web" not in found
        assert (
            "service web builds its image (tagged acme/web:${TAG}) from ./web" in manifest.sources
        )
        assert "service worker extends another service's definition" in manifest.sources

    @pytest.mark.conformance("image", "UNI-03")
    @pytest.mark.parametrize(
        ("text", "error"),
        [
            ("services:\n  db:\n    restart: always\n", "neither an image nor a build context"),
            (
                "services:\n  db:\n    image: postgres\n    volumes\n",
                "neither a key nor a list item",
            ),
            ("services:\n\tdb:\n", "tab"),
            ("name: empty\n", "without services"),
            ("services:\n  db:\n    image: Postgres:16\n", "not an image reference"),
        ],
    )
    def test_what_compose_refuses_is_a_diagnostic(self, text, error) -> None:
        manifest = ImageHelpers.compose(text)
        assert manifest.parse_error and error in manifest.parse_error

    def test_the_environment_file(self) -> None:
        assert Compose.environment('# c\nexport TAG=1.0\nNAME="a b"\nX=y # note\nbad line\n') == {
            "TAG": "1.0",
            "NAME": "a b",
            "X": "y",
        }

    def test_the_environment_file_beside_compose_is_read(self) -> None:
        compose = FileContent.from_bytes(
            "app/compose.yaml", b"services:\n  db:\n    image: postgres:${PG}\n"
        )
        manifest = ImageEcosystem().parse_in_tree(
            compose, {"app/.env": FileContent.from_bytes("app/.env", b"PG=16.4\n")}
        )
        assert [(d.name, d.spec) for d in manifest.dependencies] == [("postgres", "16.4")]


class TestThePackageGraph:
    @pytest.mark.conformance("image", "UNI-07", "image.os-packages")
    @pytest.mark.conformance("x", "x.os-packages")
    def test_dpkg_alternatives_provides_and_apt_states(self) -> None:
        status = (
            b"Package: curl\nStatus: install ok installed\nVersion: 8.5\nDepends: libcurl4 (= 8.5), mail-transport-agent | sendmail\n\n"
            b"Package: libcurl4\nStatus: install ok installed\nVersion: 8.5\nDepends: libc6 (>= 2.34)\n\n"
            b"Package: exim4\nStatus: install ok installed\nVersion: 4.97\nProvides: mail-transport-agent\n\n"
            b"Package: libc6\nStatus: install ok installed\nVersion: 2.36\n"
        )
        automatic = PackageDatabases.apt_automatic(
            b"Package: libcurl4\nArchitecture: amd64\nAuto-Installed: 1\n\nPackage: exim4\nArchitecture: all\nAuto-Installed: 1\n"
        )
        packages = [
            OsPackage(**{**p.__dict__, "requested": p.name not in automatic})
            for p in PackageDatabases.dpkg(status)
        ]
        edges = PackageGraph.edges(packages)
        names = [p.name for p in packages]
        assert sorted(names[c] for c in edges[names.index("curl")]) == ["exim4", "libcurl4"]
        # libc6 is not in apt's states: installed before apt was, so asked for as far as apt knows.
        assert PackageGraph.direct(packages, edges) == [True, False, False, True]

    def test_apk_world_provides_and_install_if(self) -> None:
        installed = (
            b"P:busybox\nV:1.36\nD:so:libc.musl\np:cmd:sh\n\n"
            b"P:musl\nV:1.2\np:so:libc.musl\n\n"
            b"P:musl-utils\nV:1.2\np:libc-utils\n\n"
            b"P:libssl3\nV:3.3\n\n"
            b"P:ssl_client\nV:1.36\ni:busybox=1.36 libssl3\n"
        )
        world = PackageDatabases.apk_world(b"busybox\nlibc-utils>=1\n")
        packages = [
            OsPackage(
                **{
                    **p.__dict__,
                    "requested": p.name in world or any(x in world for x in p.provides),
                }
            )
            for p in PackageDatabases.apk(installed)
        ]
        edges = PackageGraph.edges(packages)
        names = [p.name for p in packages]
        assert [names[c] for c in edges[names.index("busybox")]] == ["musl", "ssl_client"]
        assert names[edges[names.index("libssl3")][0]] == "ssl_client"
        assert PackageGraph.direct(packages, edges) == [True, False, True, False, False]

    def test_rpm_rich_dependencies(self) -> None:
        assert PackageDatabases.rpm_requirement("(python3-libs or python3.11-libs)") == (
            "python3-libs|python3.11-libs",
        )
        assert PackageDatabases.rpm_requirement("(a >= 1 with b)") == ("a", "b")
        assert PackageDatabases.rpm_requirement("(selinux-policy if selinux-policy-targeted)") == (
            "selinux-policy",
        )
        assert PackageDatabases.rpm_requirement("((a or b) and c)") == ()
        assert PackageDatabases.rpm_requirement("glibc") == ("glibc",)

    def test_without_requested_markers_the_roots_and_one_of_each_lone_cycle_are_direct(
        self,
    ) -> None:
        packages = [
            OsPackage("dpkg", "a", "1", requires=("b",)),
            OsPackage("dpkg", "b", "1"),
            OsPackage("dpkg", "c", "1", requires=("d",)),
            OsPackage("dpkg", "d", "1", requires=("c",)),
        ]
        assert PackageGraph.direct(packages, PackageGraph.edges(packages)) == [
            True,
            False,
            True,
            False,
        ]


class TestImageIdentity:
    @pytest.mark.conformance("image", "image.digests", "image.base-provenance")
    def test_an_oci_layout_with_a_platform_index(self) -> None:
        config = json.dumps(
            {
                "os": "linux",
                "architecture": "arm64",
                "variant": "v8",
                "created": "2026-01-01T00:00:00Z",
                "rootfs": {"diff_ids": ["sha256:" + "1" * 64]},
                "config": {
                    "Labels": {
                        "org.opencontainers.image.base.name": "docker.io/library/debian:12",
                        "org.opencontainers.image.base.digest": "sha256:" + "2" * 64,
                    }
                },
            }
        ).encode()
        archive = ImageIdentityHelpers.layout(config)
        identity = ImageIdentity.read(archive)
        assert identity.image_id == f"sha256:{hashlib.sha256(config).hexdigest()}"
        assert identity.manifest_digest == ImageIdentityHelpers.index_digest
        assert identity.references == ("docker.io/acme/app:1.0",)
        assert identity.platform == "linux/arm64/v8" and identity.layers == ("sha256:" + "1" * 64,)
        assert (identity.base_name, identity.base_digest) == (
            "docker.io/library/debian:12",
            "sha256:" + "2" * 64,
        )

    @pytest.mark.conformance("image", "UNI-03")
    def test_an_archive_cut_before_its_manifest_is_still_known_as_an_image(self) -> None:
        saved = ImageKit.docker_save([ImageKit.layer({"etc/os-release": b"ID=alpine\n"})])
        assert not ImageLayers.cut_short(saved)
        assert ImageLayers.cut_short(saved[: len(saved) // 2]) or ImageLayers.cut_short(
            saved[: len(saved) - 1024]
        )
        assert not ImageLayers.cut_short(b"\x00\xff{[<" + saved[100:])


class ImageIdentityHelpers:
    index_digest = ""

    @staticmethod
    def layout(config: bytes) -> bytes:
        def sha(data: bytes) -> str:
            return f"sha256:{hashlib.sha256(data).hexdigest()}"

        manifest = json.dumps(
            {"schemaVersion": 2, "config": {"digest": sha(config)}, "layers": []}
        ).encode()
        platform_index = json.dumps(
            {
                "schemaVersion": 2,
                "manifests": [
                    {"digest": sha(manifest), "platform": {"os": "linux", "architecture": "arm64"}}
                ],
            }
        ).encode()
        ImageIdentityHelpers.index_digest = sha(platform_index)
        top = json.dumps(
            {
                "schemaVersion": 2,
                "manifests": [
                    {
                        "digest": sha(platform_index),
                        "annotations": {
                            "io.containerd.image.name": "docker.io/acme/app:1.0",
                            "org.opencontainers.image.ref.name": "1.0",
                        },
                    }
                ],
            }
        ).encode()
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            for name, data in (
                ("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'),
                ("index.json", top),
                *(
                    (f"blobs/sha256/{sha(blob)[7:]}", blob)
                    for blob in (config, manifest, platform_index)
                ),
            ):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return buffer.getvalue()


class TestProvenanceOfImages:
    @pytest.mark.conformance("image", "UNI-17")
    @pytest.mark.conformance("x", "x.provenance")
    def test_a_digest_pinned_image_is_verified_by_that_digest(self, monkeypatch) -> None:
        from cordon_scanner.core.config import Config
        from cordon_scanner.detect.base import GraphUnit, ScanContext
        from cordon_scanner.detect.provenance import INVALID_RULE, ProvenanceDetector
        from cordon_scanner.intel import attest
        from cordon_scanner.intel.attest import Outcome, Result
        from cordon_scanner.intel.registry_client import PackageFacts
        from cordon_scanner.rules.loader import RuleLoader, RuleSet

        digest = "sha256:" + "f" * 64
        asked: list[tuple[str, str, str | None]] = []

        def facts(ecosystem, name, version):
            asked.append((ecosystem, name, version))
            return PackageFacts(
                name=name, version=version, repository="https://github.com/acme/app", attested=True
            )

        verified: list[dict] = []
        monkeypatch.setattr("cordon_scanner.intel.registry_client.RegistryClient.facts", facts)
        monkeypatch.setattr(
            "cordon_scanner.intel.registry_client.RegistryClient.attestation_payload",
            lambda e, n, v: {"bundles": [{}]},
        )
        monkeypatch.setattr(attest.SigstoreVerification, "available", lambda: True)
        outcome = {"value": Outcome.VERIFIED}

        def verify(bundle, **kwargs):
            verified.append(kwargs)
            return Result(outcome["value"], "stub")

        monkeypatch.setattr(attest.SigstoreVerification, "verify", verify)
        dependency = Dependency(
            purl="pkg:docker/ghcr.io/acme/app",
            ecosystem="image",
            name="ghcr.io/acme/app",
            direct=True,
            integrity=digest,
        )
        ctx = ScanContext(
            config=Config.default(), rules=RuleSet(RuleLoader.load_builtin()), offline=False
        )
        assert list(ProvenanceDetector().inspect(GraphUnit(dependencies=(dependency,)), ctx)) == []
        assert asked == [("image", "ghcr.io/acme/app", digest)]
        assert verified[0]["digest_hex"] == "f" * 64 and verified[0]["algorithm"] == "sha256"
        outcome["value"] = Outcome.INVALID
        assert [
            f.rule_id
            for f in ProvenanceDetector().inspect(GraphUnit(dependencies=(dependency,)), ctx)
        ] == [INVALID_RULE]
