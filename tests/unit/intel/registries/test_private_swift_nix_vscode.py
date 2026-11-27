"""The readers for Swift (SE-0292), a Nix binary cache and Open VSX, asked through a private registry: what each makes of
the registry's own documents."""

from __future__ import annotations

import io
import json
import urllib.error
from email.message import Message
from typing import Any

import pytest

from cordon_scanner.intel.registries.private_registries import PrivateRegistries, PrivateRegistry
from cordon_scanner.intel.registries.registry_client import PackageNotFound

TOKEN = "s3cr3t-registry-token-value"
SWIFT = PrivateRegistry("https://swift.acme.example/registry", "ACME_TOKEN")
CACHE = PrivateRegistry("https://cache.acme.example", "ACME_TOKEN")
EXTENSIONS = PrivateRegistry("https://openvsx.acme.example", "ACME_TOKEN")
STORE_HASH = "0123456789abcdfghijklmnpqrsvwxyz"


class Answers:
    def __init__(self, answers: dict[str, bytes | dict[str, Any]]) -> None:
        self.answers = answers
        self.requests: list[tuple[str, dict[str, str]]] = []

    def opener(self, *handlers: Any) -> Answers:
        return self

    def open(self, request, timeout: float = 0):
        self.requests.append((request.full_url, dict(request.header_items())))
        body = self.answers.get(request.full_url)
        if body is None:
            raise urllib.error.HTTPError(
                request.full_url, 404, "not found", Message(), io.BytesIO(b"")
            )
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        response = io.BytesIO(data)
        response.headers = Message()  # type: ignore[attr-defined]
        response.__enter__ = lambda: response  # type: ignore[method-assign,assignment]
        response.__exit__ = lambda *exc: None  # type: ignore[method-assign,assignment]
        return response


class Networked:
    """What a test of a reader asked through the private registry needs: the network replaced by canned answers."""

    @pytest.fixture
    def network(self, monkeypatch):
        def install(answers):
            fake = Answers(answers)
            monkeypatch.setattr("urllib.request.build_opener", fake.opener)
            monkeypatch.setenv("ACME_TOKEN", TOKEN)
            return fake

        return install


class TestSwift(Networked):
    ROOT = "https://swift.acme.example/registry/acme/widget"

    def answers(self):
        return {
            self.ROOT: {
                "releases": {
                    "2.0.0": {"url": f"{self.ROOT}/2.0.0", "problem": {"status": 410}},
                    "1.0.0": {"url": f"{self.ROOT}/1.0.0"},
                }
            },
            f"{self.ROOT}/1.0.0": {
                "id": "acme.widget",
                "version": "1.0.0",
                "resources": [
                    {"name": "source-archive", "type": "application/zip", "checksum": "ab" * 32}
                ],
            },
        }

    def test_a_release_gives_its_archive_checksum_and_the_latest_is_not_a_withdrawn_one(
        self, network
    ):
        fake = network(self.answers())
        facts = PrivateRegistries.facts(SWIFT, "swift", "acme.widget", "1.0.0")
        assert facts.digests == ("sha256:" + "ab" * 32,)
        assert facts.latest == "1.0.0" and facts.releases == 2 and not facts.yanked
        assert all(h.get("Authorization") == f"Bearer {TOKEN}" for _u, h in fake.requests)
        assert any("vnd.swift.registry.v1" in str(h.get("Accept")) for _u, h in fake.requests)

    def test_a_release_the_registry_marks_with_a_problem_is_withdrawn(self, network):
        network(self.answers())
        facts = PrivateRegistries.facts(SWIFT, "swift", "acme.widget", "2.0.0")
        assert facts.yanked and "withdrawn" in (facts.yanked_reason or "")

    def test_a_version_the_registry_does_not_hold_is_not_held(self, network):
        network(self.answers())
        assert PrivateRegistries.facts(SWIFT, "swift", "acme.widget", "9.9.9").yanked

    def test_a_package_the_registry_does_not_know_is_not_found(self, network):
        network({})
        with pytest.raises(PackageNotFound):
            PrivateRegistries.facts(SWIFT, "swift", "acme.widget", "1.0.0")


class TestNix(Networked):
    def test_a_store_path_gives_the_hashes_the_cache_publishes(self, network):
        narinfo = (
            f"StorePath: /nix/store/{STORE_HASH}-hello-2.12\nURL: nar/x.nar.xz\nFileHash: sha256:aaaa\n"
            "NarHash: sha256:bbbb\nNarSize: 1\n"
        ).encode()
        network({f"https://cache.acme.example/{STORE_HASH}.narinfo": narinfo})
        facts = PrivateRegistries.facts(CACHE, "nix", f"{STORE_HASH}-hello", None)
        assert facts.digests == ("sha256:aaaa", "sha256:bbbb")

    def test_a_narinfo_for_another_store_path_is_refused(self, network):
        other = "x" * 0 + "9" * 32
        network(
            {
                f"https://cache.acme.example/{STORE_HASH}.narinfo": f"StorePath: /nix/store/{other}-x\n".encode()
            }
        )
        with pytest.raises(Exception, match="another store path"):
            PrivateRegistries.facts(CACHE, "nix", STORE_HASH, None)

    def test_a_name_that_is_not_a_store_hash_is_not_asked(self, network):
        fake = network({})
        with pytest.raises(Exception, match="store path hash"):
            PrivateRegistries.facts(CACHE, "nix", "../../etc", None)
        assert fake.requests == []


class TestOpenVsx(Networked):
    ROOT = "https://openvsx.acme.example/api/acme/theme"

    def answers(self):
        return {
            self.ROOT: {
                "allVersions": {"latest": f"{self.ROOT}/2.0.0", "2.0.0": "u", "1.0.0": "u"}
            },
            f"{self.ROOT}/1.0.0": {
                "files": {"sha256": f"{self.ROOT}/1.0.0/file/acme.theme-1.0.0.sha256"}
            },
            f"{self.ROOT}/1.0.0/file/acme.theme-1.0.0.sha256": ("cd" * 32 + "\n").encode(),
        }

    def test_a_version_gives_the_sha256_the_registry_publishes_for_its_vsix(self, network):
        fake = network(self.answers())
        facts = PrivateRegistries.facts(EXTENSIONS, "vscode", "acme.theme", "1.0.0")
        assert facts.digests == ("sha256:" + "cd" * 32,)
        assert facts.releases == 2 and facts.latest == "2.0.0"
        assert all(h.get("Authorization") == f"Bearer {TOKEN}" for _u, h in fake.requests)

    def test_a_version_the_registry_does_not_hold_is_not_held(self, network):
        network(self.answers())
        assert PrivateRegistries.facts(EXTENSIONS, "vscode", "acme.theme", "0.0.1").yanked

    def test_an_address_in_a_document_on_another_host_is_not_followed(self, network):
        answers = self.answers()
        answers[f"{self.ROOT}/1.0.0"] = {"files": {"sha256": "https://elsewhere.example/x.sha256"}}
        fake = network(answers)
        with pytest.raises(Exception, match=r"refusing to ask elsewhere\.example"):
            PrivateRegistries.facts(EXTENSIONS, "vscode", "acme.theme", "1.0.0")
        assert all("elsewhere" not in url for url, _ in fake.requests)
