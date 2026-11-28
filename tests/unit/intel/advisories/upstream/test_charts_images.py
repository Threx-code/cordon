"""A Helm chart's and a container image's upstream, read from real answers: an excerpt of a chart repository's
`index.yaml` (charts.jetstack.io) and an image's index, manifest and configuration (Docker Hub's `traefik:v3.0.4`),
captured once (`charts_images_records.json`)."""

from __future__ import annotations

import json
from typing import Any, ClassVar

import pytest

from cordon_scanner.foundation.results import Dependency
from cordon_scanner.intel.advisories.upstream import charts_images
from cordon_scanner.intel.advisories.upstream.base import Unnamed, Upstream
from cordon_scanner.intel.advisories.upstream.charts_images import (
    ChartIndex,
    ChartsImages,
    Hosts,
    ImageName,
    OciConfig,
)
from cordon_scanner.intel.advisories.upstream_advisories import SUPPORTED, Upstreams
from support import ROOT

RECORDS: dict[str, Any] = json.loads(
    (ROOT / "tests/unit/intel/advisories/upstream/charts_images_records.json").read_text(
        encoding="utf-8"
    )
)
INDEX: str = RECORDS["chart_index_excerpt"]
IMAGE: dict[str, Any] = RECORDS["image"]


class Asked:
    """What tag inference was asked: the repository it would look in and the version it would look for."""

    calls: ClassVar[list[tuple[Any, ...]]] = []

    @classmethod
    def install(cls, monkeypatch: pytest.MonkeyPatch) -> type[Asked]:
        cls.calls = []
        monkeypatch.setattr(charts_images.Inference, "inferred", staticmethod(cls.inferred))
        return cls

    @classmethod
    def inferred(
        cls, first: Any, homes: Any, version: str, names: Any, how: str, archive: Any = None
    ) -> Upstream:
        cls.calls.append((tuple(h for h in homes if h), version, tuple(names), how))
        return Upstream({"asked": version}, how)


class FakeRegistry:
    """The captured answers by reference, as `RegistryImage` serves them."""

    def __init__(self, registry: str, repository: str) -> None:
        assert (registry, repository) == ("registry-1.docker.io", "library/traefik")

    def manifest(self, reference: str) -> tuple[bytes, str]:
        if reference == IMAGE["tag"]:
            return json.dumps(IMAGE["index"]).encode(), str(IMAGE["index"].get("mediaType"))
        assert reference == IMAGE["manifest_digest"]
        return json.dumps(IMAGE["manifest"]).encode(), str(IMAGE["manifest"].get("mediaType"))

    def blob(self, digest: str, pull: Any) -> bytes:
        assert digest == IMAGE["manifest"]["config"]["digest"]
        return json.dumps(IMAGE["config"]).encode()


class TestTheRegistryCoversChartsAndImages:
    def test_both_are_supported_and_dispatched(self) -> None:
        assert {"helm", "image"} <= SUPPORTED
        assert Upstreams.helm and Upstreams.image


class TestAChartRepositoryIndex:
    def test_a_chart_versions_metadata_is_read(self) -> None:
        fields = ChartIndex.entry(INDEX, "cert-manager", "v1.14.4")
        assert fields is not None
        assert fields["appVersion"] == "v1.14.4"
        assert fields["sources"] == ["https://github.com/cert-manager/cert-manager"]
        assert fields["home"] == "https://github.com/cert-manager/cert-manager"

    def test_the_next_chart_is_not_read_as_this_one(self) -> None:
        assert ChartIndex.entry(INDEX, "cert-manager", "v0.29.0") is None
        other = ChartIndex.entry(INDEX, "cert-manager-approver-policy", "v0.29.0")
        assert other is not None and other["appVersion"] == "v0.29.0"

    def test_a_version_the_index_does_not_list_is_nothing(self) -> None:
        assert ChartIndex.entry(INDEX, "cert-manager", "v9.9.9") is None
        assert ChartIndex.entry(INDEX, "no-such-chart", "v1.14.4") is None

    def test_a_chart_is_matched_through_its_application(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asked = Asked.install(monkeypatch)
        monkeypatch.setattr(
            charts_images.Fetch, "get", staticmethod(lambda url, limit=0: INDEX.encode())
        )
        dependency = Dependency(
            purl="pkg:helm/cert-manager@v1.14.4",
            ecosystem="helm",
            name="cert-manager",
            version="v1.14.4",
            resolved_from="https://charts.jetstack.io",
        )
        assert isinstance(ChartsImages.helm(dependency), Upstream)
        homes, version, names, _ = asked.calls[0]
        assert version == "v1.14.4" and names == ("cert-manager",)
        assert "https://github.com/cert-manager/cert-manager" in homes

    def test_a_repository_named_otherwise_is_left_unchecked(self) -> None:
        dependency = Dependency(
            purl="pkg:helm/x@1",
            ecosystem="helm",
            name="x",
            version="1",
            resolved_from="file://../x",
        )
        assert isinstance(ChartsImages.helm(dependency), Unnamed)


class TestAnImage:
    def test_its_labels_name_the_source_and_the_release(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asked = Asked.install(monkeypatch)
        from cordon_scanner.intel.registries import registry_image

        monkeypatch.setattr(registry_image, "RegistryImage", FakeRegistry)
        dependency = Dependency(
            purl="pkg:docker/traefik@v3.0.4", ecosystem="image", name="traefik", version="v3.0.4"
        )
        assert isinstance(ChartsImages.image(dependency), Upstream)
        homes, version, names, how = asked.calls[0]
        assert homes == ("https://github.com/traefik/traefik",) and version == "v3.0.4"
        assert names == ("traefik",) and "library/traefik:v3.0.4" in how

    def test_a_revision_label_is_asked_as_the_commit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from cordon_scanner.intel.registries import registry_image

        labels = IMAGE["config"]["config"]["Labels"]
        revised = {**IMAGE["config"], "config": {**IMAGE["config"]["config"], "Labels": {**labels}}}
        revised["config"]["Labels"]["org.opencontainers.image.revision"] = "a" * 40

        class Revised(FakeRegistry):
            def blob(self, digest: str, pull: Any) -> bytes:
                return json.dumps(revised).encode()

        monkeypatch.setattr(registry_image, "RegistryImage", Revised)
        dependency = Dependency(
            purl="pkg:docker/traefik@v3.0.4", ecosystem="image", name="traefik", version="v3.0.4"
        )
        upstream = ChartsImages.image(dependency)
        assert isinstance(upstream, Upstream) and upstream.query == {"commit": "a" * 40}
        assert upstream.inferred  # the image's own claim, never a verified origin


class TestAnImageName:
    @pytest.mark.parametrize(
        ("name", "split"),
        [
            ("traefik", ("registry-1.docker.io", "library/traefik")),
            ("bitnami/nginx", ("registry-1.docker.io", "bitnami/nginx")),
            ("docker.io/bitnami/redis", ("registry-1.docker.io", "bitnami/redis")),
            ("ghcr.io/owner/tool", ("ghcr.io", "owner/tool")),
            ("localhost:5000/team/app", ("localhost:5000", "team/app")),
        ],
    )
    def test_it_splits_as_the_image_adapter_does(self, name: str, split: tuple[str, str]) -> None:
        from cordon_scanner.ecosystems.infra.image import ImageReference

        assert ImageName.split(name) == split
        reference = ImageReference.parse(name)
        assert reference is not None
        assert reference.repository == split[1]

    @pytest.mark.parametrize("name", ["", "../x", "a/../b", "a//b", "UPPER/../x", "a?b", "a#b"])
    def test_a_hostile_name_is_refused(self, name: str) -> None:
        assert ImageName.split(name) is None


class TestAHostileRegistry:
    """What a registry answers is untrusted: anything but an object at each step is a ValueError, never another error."""

    @pytest.mark.parametrize(
        ("manifest", "config"),
        [
            ([], {}),
            (None, {}),
            ({"config": None}, {}),
            ({"config": {"digest": 3}}, {}),
            ({"manifests": "x"}, {}),
            ({"config": {"digest": "sha256:" + "0" * 64}}, []),
        ],
    )
    def test_a_malformed_answer_is_a_value_error(
        self, monkeypatch: pytest.MonkeyPatch, manifest: Any, config: Any
    ) -> None:
        from cordon_scanner.intel.registries import registry_image

        class Hostile:
            def __init__(self, registry: str, repository: str) -> None:
                pass

            def manifest(self, reference: str) -> tuple[bytes, str]:
                return json.dumps(manifest).encode(), ""

            def blob(self, digest: str, pull: Any) -> bytes:
                return json.dumps(config).encode()

        monkeypatch.setattr(registry_image, "RegistryImage", Hostile)
        with pytest.raises(ValueError):
            OciConfig.of("registry.example.com", "a/b", "1.0")


class TestAHostNamedByScannedContent:
    @pytest.mark.parametrize(
        "host",
        [
            "localhost",
            "localhost:5000",
            "127.0.0.1",
            "[::1]",
            "10.0.0.5:443",
            "192.168.1.1",
            "169.254.169.254",
            "intranet",
            "svc.local",
            "db.internal",
            "",
        ],
    )
    def test_a_local_or_private_host_is_not_asked(self, host: str) -> None:
        assert not Hosts.public(host)

    @pytest.mark.parametrize(
        "host", ["registry-1.docker.io", "ghcr.io", "charts.jetstack.io:443", "8.8.8.8"]
    )
    def test_a_public_host_is_asked(self, host: str) -> None:
        assert Hosts.public(host)

    def test_a_chart_repository_on_this_machine_is_left_unchecked(self) -> None:
        https = Dependency(
            purl="pkg:helm/x@1",
            ecosystem="helm",
            name="x",
            version="1",
            resolved_from="https://127.0.0.1:8080/c",
        )
        assert isinstance(ChartsImages.helm(https), Unnamed)
        oci = Dependency(
            purl="pkg:helm/x@1",
            ecosystem="helm",
            name="x",
            version="1",
            resolved_from="oci://localhost:5000/c",
        )
        with pytest.raises(ValueError):
            ChartsImages.helm(oci)


class TestAnOciChartTag:
    def test_build_metadata_is_asked_as_helm_stores_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asked: list[tuple[str, str, str]] = []

        def of(registry: str, repository: str, reference: str) -> dict[str, Any]:
            asked.append((registry, repository, reference))
            return {}

        monkeypatch.setattr(OciConfig, "of", staticmethod(of))
        dependency = Dependency(
            purl="pkg:helm/chart@1.2.3+build.4",
            ecosystem="helm",
            name="chart",
            version="1.2.3+build.4",
            resolved_from="oci://registry.example.com/charts",
        )
        ChartsImages.helm(dependency)
        assert asked == [("registry.example.com", "charts/chart", "1.2.3_build.4")]
