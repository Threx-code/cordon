"""A private registry is asked, for every ecosystem that has a reader, with the operator's credential and nowhere else.

The transport is substituted at `urllib.request.build_opener`: every request is seen, and answers 404 so no reader
goes further than its first question. A request to any host but the private registry is a failure, and so is one that
leaves without the credential."""

from __future__ import annotations

import io
import urllib.error
from email.message import Message
from typing import Any, ClassVar

import pytest

from cordon_scanner.intel.registries.private_registries import PrivateRegistries, PrivateRegistry
from cordon_scanner.intel.registries.registry_client import PackageNotFound, RegistryError

TOKEN = "s3cr3t-registry-token-value"
REGISTRY = PrivateRegistry("https://registry.acme.example/artifacts", "ACME_TOKEN")
CHARTS = PrivateRegistry("https://charts.acme.example/stable", "ACME_TOKEN")


class Names:
    SPECIAL: ClassVar[dict[str, str]] = {
        "ansible": "acme.widget",
        "maven": "org.acme:widget",
        "gradle": "org.acme:widget",
        "composer": "acme/widget",
        "terraform": "acme/widget/aws",
        "actions": "acme/widget",
        "swift": "acme.widget",
        "vscode": "acme.widget",
        "nix": "a" * 32,
    }

    @classmethod
    def of(cls, ecosystem: str) -> str:
        return cls.SPECIAL.get(ecosystem, "widget")


class Recording:
    def __init__(self) -> None:
        self.requests: list[tuple[str, dict[str, str]]] = []

    def opener(self, *handlers: Any) -> Recording:
        return self

    def open(self, request, timeout: float = 0):
        self.requests.append((request.full_url, dict(request.header_items())))
        raise urllib.error.HTTPError(request.full_url, 404, "not found", Message(), io.BytesIO(b""))


class TestEveryEcosystemWithAReader:
    @pytest.mark.parametrize("ecosystem", sorted(PrivateRegistries.supported()))
    def test_the_registry_alone_is_asked_and_with_the_credential(
        self, ecosystem, monkeypatch
    ) -> None:
        recording = Recording()
        monkeypatch.setattr("urllib.request.build_opener", recording.opener)
        monkeypatch.setenv("ACME_TOKEN", TOKEN)
        registry = CHARTS if ecosystem == "helm" else REGISTRY
        name = Names.of(ecosystem)
        if ecosystem == "image":
            name = f"{registry.host}/acme/widget"
        with pytest.raises((PackageNotFound, RegistryError)) as outcome:
            PrivateRegistries.facts(registry, ecosystem, name, "1.0.0", source=registry.base)
        assert recording.requests, f"{ecosystem}: nothing was asked of the registry"
        for url, headers in recording.requests:
            assert url == registry.base or url.startswith(
                (registry.base + "/", f"https://{registry.host}/")
            ), (ecosystem, url)
            assert {k.lower(): v for k, v in headers.items()}.get(
                "authorization"
            ) == f"Bearer {TOKEN}", (
                ecosystem,
                url,
            )
        assert TOKEN not in str(outcome.value)

    @pytest.mark.parametrize(
        "ecosystem", sorted(PrivateRegistries.supported() - {"npm", "pypi", "image", "helm"})
    )
    def test_a_public_registry_is_never_asked_about_a_private_package(
        self, ecosystem, monkeypatch
    ) -> None:
        recording = Recording()
        monkeypatch.setattr("urllib.request.build_opener", recording.opener)
        monkeypatch.setenv("ACME_TOKEN", TOKEN)
        with pytest.raises((PackageNotFound, RegistryError)):
            PrivateRegistries.facts(REGISTRY, ecosystem, Names.of(ecosystem), "1.0.0")
        assert all(
            url.startswith("https://registry.acme.example/") for url, _ in recording.requests
        ), ecosystem

    def test_every_ecosystem_has_a_reader(self) -> None:
        from cordon_scanner.ecosystems.registry import EcosystemRegistry

        assert PrivateRegistries.supported() == frozenset(EcosystemRegistry.BY_ID) | {"vscode"}

    def test_an_ecosystem_the_scanner_does_not_know_says_so_and_asks_nothing(
        self, monkeypatch
    ) -> None:
        recording = Recording()
        monkeypatch.setattr("urllib.request.build_opener", recording.opener)
        monkeypatch.setenv("ACME_TOKEN", TOKEN)
        with pytest.raises(RegistryError, match="no private-registry reader"):
            PrivateRegistries.facts(REGISTRY, "nosuch", "widget", "1.0.0")
        assert recording.requests == []


class TestTheRouteStaysWhereItWasSet:
    def test_it_is_gone_when_the_question_is_answered(self, monkeypatch) -> None:
        from cordon_scanner.intel.registries.private_route import PrivateRoute

        recording = Recording()
        monkeypatch.setattr("urllib.request.build_opener", recording.opener)
        monkeypatch.setenv("ACME_TOKEN", TOKEN)
        with pytest.raises((PackageNotFound, RegistryError)):
            PrivateRegistries.facts(REGISTRY, "cargo", "widget", "1.0.0")
        assert PrivateRoute.current() is None

    def test_another_thread_asks_the_public_registry_without_the_credential(
        self, monkeypatch
    ) -> None:
        import threading

        from cordon_scanner.intel.registries.private_route import PrivateRoute, Route

        seen: list[tuple[str, dict[str, str]]] = []
        route = Route(
            REGISTRY.base,
            REGISTRY.host,
            f"Bearer {TOKEN}",
            {"https://crates.io": ""},
            "ACME_TOKEN",
        )
        with PrivateRoute.use(route):
            worker = threading.Thread(
                target=lambda: seen.append(PrivateRoute.apply("https://crates.io/api/v1/crates/x"))
            )
            worker.start()
            worker.join()
            inside = PrivateRoute.apply("https://crates.io/api/v1/crates/x")
        assert seen == [("https://crates.io/api/v1/crates/x", {})]
        assert inside == (f"{REGISTRY.base}/api/v1/crates/x", {"Authorization": f"Bearer {TOKEN}"})

    def test_a_redirect_to_another_host_is_refused_and_carries_nothing(self) -> None:
        from cordon_scanner.intel.registries.private_route import PrivateRoute, Route

        route = Route(
            REGISTRY.base,
            REGISTRY.host,
            f"Bearer {TOKEN}",
            {"https://crates.io": ""},
            "ACME_TOKEN",
        )
        with PrivateRoute.use(route), pytest.raises(RegistryError) as refused:
            PrivateRoute.apply("https://cdn.elsewhere.example/blob")
        assert TOKEN not in str(refused.value) and "ACME_TOKEN" in str(refused.value)

    def test_a_look_alike_host_and_a_path_outside_the_base_are_refused(self) -> None:
        from cordon_scanner.intel.registries.private_route import PrivateRoute, Route

        route = Route(
            REGISTRY.base,
            REGISTRY.host,
            f"Bearer {TOKEN}",
            {"https://crates.io": ""},
            "ACME_TOKEN",
        )
        with PrivateRoute.use(route):
            for url in (
                "https://crates.io.evil.example/x",
                "https://registry.acme.example.evil.example/artifacts/x",
                "http://crates.io/x",
            ):
                with pytest.raises(RegistryError):
                    PrivateRoute.apply(url)
