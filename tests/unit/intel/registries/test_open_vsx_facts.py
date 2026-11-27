"""What the public Open VSX registry says about an extension (`ExtensionRegistries.vscode`): its versions, whether the one asked
for is held, the SHA-256 it publishes, and what an unknown or unreachable registry is called. The registry is a table of answers."""

from __future__ import annotations

from typing import Any

import pytest

from cordon_scanner.intel.registries.readers.open_vsx import ExtensionRegistries
from cordon_scanner.intel.registries.registry_http import RegistryHttp
from cordon_scanner.intel.registries.registry_request import PackageNotFound, RegistryError

API = "https://open-vsx.org/api/acme/widget"
DIGEST = "a" * 64


class Registry:
    @staticmethod
    def serve(monkeypatch: pytest.MonkeyPatch, answers: dict[str, Any]) -> list[str]:
        asked: list[str] = []

        def json(url: str) -> Any:
            asked.append(url)
            answer = answers.get(url)
            if isinstance(answer, BaseException):
                raise answer
            if answer is None:
                raise PackageNotFound(f"{url} is not on the registry")
            return answer

        def text(url: str) -> str:
            asked.append(url)
            return str(answers[url])

        monkeypatch.setattr(RegistryHttp, "json", staticmethod(json))
        monkeypatch.setattr(RegistryHttp, "text", staticmethod(text))
        return asked

    LISTING = {
        "allVersions": {
            "latest": f"{API}/latest",
            "pre-release": f"{API}/pre-release",
            "1.0.0": f"{API}/1.0.0",
            "1.1.0": f"{API}/1.1.0",
        }
    }
    FILES = "https://open-vsx.org/api/acme/widget/1.1.0/file/acme.widget-1.1.0.sha256"


class TestWhatOpenVsxSays:
    @pytest.mark.conformance("vscode", "UNI-16")
    def test_a_held_version_carries_the_digest_the_registry_publishes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        Registry.serve(
            monkeypatch,
            {
                API: Registry.LISTING,
                f"{API}/1.1.0": {"files": {"sha256": Registry.FILES}},
                "https://openvsx.eclipsecontent.org/acme/widget/1.1.0/acme.widget-1.1.0.sha256": f"{DIGEST}  acme.widget-1.1.0.vsix\n",
            },
        )
        facts = ExtensionRegistries.vscode("acme.widget", "1.1.0")
        assert facts.digests == (f"sha256:{DIGEST}",) and not facts.yanked
        assert facts.releases == 2 and facts.latest == "1.1.0"

    @pytest.mark.conformance("vscode", "UNI-16")
    def test_a_version_the_registry_does_not_hold_is_withdrawn(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        Registry.serve(monkeypatch, {API: Registry.LISTING})
        facts = ExtensionRegistries.vscode("acme.widget", "9.9.9")
        assert facts.yanked and facts.yanked_reason == "not a version the registry holds"

    @pytest.mark.conformance("vscode", "UNI-16")
    def test_a_digest_link_off_the_file_host_is_not_followed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asked = Registry.serve(
            monkeypatch,
            {
                API: Registry.LISTING,
                f"{API}/1.1.0": {"files": {"sha256": "https://evil.example/x.sha256"}},
            },
        )
        with pytest.raises(RegistryError):
            ExtensionRegistries.vscode("acme.widget", "1.1.0")
        assert all("evil.example" not in url for url in asked)

    @pytest.mark.conformance("vscode", "UNI-16")
    def test_an_extension_the_registry_does_not_have_is_named(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        Registry.serve(monkeypatch, {})
        with pytest.raises(PackageNotFound):
            ExtensionRegistries.vscode("acme.widget", "1.0.0")

    @pytest.mark.conformance("vscode", "UNI-22")
    def test_a_registry_that_cannot_be_reached_is_an_error_not_an_answer(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        Registry.serve(monkeypatch, {API: RegistryError("connection timed out")})
        with pytest.raises(RegistryError):
            ExtensionRegistries.vscode("acme.widget", "1.0.0")

    @pytest.mark.parametrize("name", ["widget", "acme.", ".widget", "../etc.passwd", "a b.c"])
    def test_a_name_that_is_not_publisher_dot_extension_is_refused_before_asking(
        self, monkeypatch: pytest.MonkeyPatch, name: str
    ) -> None:
        asked = Registry.serve(monkeypatch, {})
        with pytest.raises(RegistryError):
            ExtensionRegistries.vscode(name, "1.0.0")
        assert asked == []
