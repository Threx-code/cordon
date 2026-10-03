"""G5: the online questions for crates.io, RubyGems, NuGet, Go, Maven Central, Packagist, pub.dev and Hex.

No test here makes a request. `MoreRegistries._get` is replaced with a fixed map of URL to body, and
every reader is checked against the shape its registry really serves (recorded from live answers when
the readers were written): withdrawal, latest, hashes, provenance, and the malformed and hostile cases
a registry answer can carry.
"""

from __future__ import annotations

import base64
import gzip
import io
import json
import urllib.error
from typing import Any

import pytest

from cordon_scanner.core.config import Config
from cordon_scanner.core.content import FileContent
from cordon_scanner.core.models import Dependency, Scope
from cordon_scanner.detect.base import GraphUnit, ScanContext
from cordon_scanner.detect.registry import (
    CONFUSABLE_ECOSYSTEMS,
    REGISTRY_ECOSYSTEMS,
    RegistryDetector,
    RegistryEvidence,
)
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.intel import more_registries
from cordon_scanner.intel.more_registries import MoreRegistries
from cordon_scanner.intel.registry_client import (
    PackageFacts,
    PackageNotFound,
    RegistryClient,
    RegistryError,
)
from cordon_scanner.rules.loader import RuleLoader, RuleSet

SHA256 = "ab" * 32
SHA512_B64 = base64.b64encode(bytes(range(64))).decode()


class Served:
    """A fixed registry: URL to body, with anything unlisted a 404."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.asked: list[str] = []

    def __call__(self, url: str, *, accept: str = "application/json") -> bytes:
        self.asked.append(url)
        if url not in self.answers:
            raise PackageNotFound(f"no {url}")
        value = self.answers[url]
        if isinstance(value, Exception):
            raise value
        if isinstance(value, bytes):
            return value
        if isinstance(value, str):
            return value.encode()
        return json.dumps(value).encode()


class RegistryFixtures:
    """A fixed registry in place of the network; every test class that needs one inherits it."""

    @pytest.fixture
    def serve(self, monkeypatch):
        def install(answers: dict[str, Any]) -> Served:
            served = Served(answers)
            monkeypatch.setattr(MoreRegistries, "_get", staticmethod(served))
            return served

        return install


class TestTransport:
    class _Response:
        def __init__(self, body: bytes, encoding: str = "") -> None:
            self.body, self.headers = body, {"Content-Encoding": encoding}

        def read(self, limit: int) -> bytes:
            return self.body[:limit]

        def __enter__(self):
            return self

        def __exit__(self, *exc) -> None:
            return None

    class _Opener:
        def __init__(self, outcomes: list[Any]) -> None:
            self.outcomes = outcomes

        def open(self, request, timeout):
            outcome = self.outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

    @pytest.fixture
    def opener(self, monkeypatch):
        def install(*outcomes: Any) -> None:
            fake = self._Opener(list(outcomes))
            monkeypatch.setattr(more_registries.urllib.request, "build_opener", lambda *a: fake)
            monkeypatch.setattr(more_registries.time, "sleep", lambda s: None)

        return install

    @staticmethod
    def _http(code: int) -> urllib.error.HTTPError:
        return urllib.error.HTTPError("https://crates.io/x", code, "status", {}, io.BytesIO(b""))  # type: ignore[arg-type]

    def test_a_plain_http_url_is_refused_before_any_request(self) -> None:
        with pytest.raises(RegistryError, match="non-HTTPS"):
            MoreRegistries._get("http://crates.io/api/v1/crates/serde")

    def test_a_gzip_body_is_decompressed(self, opener) -> None:
        opener(self._Response(gzip.compress(b'{"ok": 1}'), "gzip"))
        assert MoreRegistries._json("https://api.nuget.org/x") == {"ok": 1}

    def test_a_body_that_expands_past_the_ceiling_is_refused(self, opener, monkeypatch) -> None:
        monkeypatch.setattr(more_registries, "_MAX_GZIP_BYTES", 1024)
        opener(self._Response(gzip.compress(b"0" * 10_000), "gzip"))
        with pytest.raises(RegistryError, match="expands past"):
            MoreRegistries._get("https://api.nuget.org/x")

    def test_a_corrupt_gzip_body_is_an_error_not_a_crash(self, opener) -> None:
        opener(self._Response(b"\x1f\x8bnot-gzip", "gzip"))
        with pytest.raises(RegistryError, match="compressed"):
            MoreRegistries._get("https://api.nuget.org/x")

    def test_an_oversized_body_is_refused(self, opener, monkeypatch) -> None:
        monkeypatch.setattr(more_registries.base, "MAX_RESPONSE_BYTES", 8)
        opener(self._Response(b"0123456789"))
        with pytest.raises(RegistryError, match="exceeded"):
            MoreRegistries._get("https://crates.io/x")

    @pytest.mark.parametrize("code", [404, 410])
    def test_not_found_and_gone_are_definite_answers(self, opener, code) -> None:
        opener(self._http(code))
        with pytest.raises(PackageNotFound):
            MoreRegistries._get("https://proxy.golang.org/x")

    def test_a_busy_registry_is_asked_again(self, opener) -> None:
        opener(self._http(503), self._Response(b"{}"))
        assert MoreRegistries._json("https://crates.io/x") == {}

    def test_a_registry_busy_every_time_is_an_error(self, opener) -> None:
        opener(self._http(503), self._http(503), self._http(503))
        with pytest.raises(RegistryError, match="HTTP 503"):
            MoreRegistries._get("https://crates.io/x")

    def test_a_refusal_is_not_retried(self, opener) -> None:
        opener(self._http(403))
        with pytest.raises(RegistryError, match="HTTP 403"):
            MoreRegistries._get("https://crates.io/x")

    def test_a_connection_failure_is_retried_then_reported(self, opener) -> None:
        opener(OSError("down"), OSError("down"), OSError("down"))
        with pytest.raises(RegistryError, match="OSError"):
            MoreRegistries._get("https://crates.io/x")

    def test_a_body_that_is_not_json_is_an_error(self, opener) -> None:
        opener(self._Response(b"<html>"))
        with pytest.raises(RegistryError, match="unreadable"):
            MoreRegistries._json("https://crates.io/x")


class TestDispatch(RegistryFixtures):
    def test_gradle_is_answered_by_maven_central(self, serve) -> None:
        serve({"https://repo.maven.apache.org/maven2/org/x/lib/maven-metadata.xml": "<metadata/>"})
        assert MoreRegistries.facts("gradle", "org.x:lib", None).name == "org.x:lib"

    def test_an_unknown_ecosystem_is_an_error(self) -> None:
        with pytest.raises(RegistryError, match="no registry configured"):
            MoreRegistries.facts("conan", "zlib", "1.3")

    def test_the_client_routes_these_ecosystems_here(self, serve) -> None:
        RegistryClient._cached_facts.cache_clear()
        serve({"https://crates.io/api/v1/crates/routed": {"crate": {}, "versions": []}})
        assert RegistryClient.facts("cargo", "routed", "1.0.0").name == "routed"
        RegistryClient._cached_facts.cache_clear()

    def test_the_client_still_refuses_what_nobody_answers(self) -> None:
        with pytest.raises(RegistryError):
            RegistryClient._cached_facts("swift", "x", "1")


class TestCrates(RegistryFixtures):
    URL = "https://crates.io/api/v1/crates/demo"

    def test_a_yanked_version_its_checksum_and_the_latest(self, serve) -> None:
        serve(
            {
                self.URL: {
                    "crate": {
                        "max_stable_version": "2.0.0",
                        "repository": "https://github.com/o/demo",
                        "created_at": "2020-01-01T00:00:00Z",
                    },
                    "versions": [
                        {"num": "2.0.0", "checksum": "cd" * 32},
                        {
                            "num": "1.0.0",
                            "yanked": True,
                            "yank_message": "broken build",
                            "checksum": SHA256,
                        },
                    ],
                }
            }
        )
        facts = MoreRegistries.cargo("demo", "1.0.0")
        assert facts.yanked and facts.yanked_reason == "broken build"
        assert facts.digests == (SHA256,) and facts.latest == "2.0.0" and facts.releases == 2
        assert facts.repository == "https://github.com/o/demo"

    def test_a_version_the_crate_does_not_list_has_no_answer(self, serve) -> None:
        serve({self.URL: {"crate": {"newest_version": "0.1.0"}, "versions": [{"num": "0.1.0"}]}})
        facts = MoreRegistries.cargo("demo", "9.9.9")
        assert not facts.yanked and facts.digests == () and facts.latest == "0.1.0"

    def test_hostile_field_types_produce_an_empty_answer(self, serve) -> None:
        serve({self.URL: {"crate": ["not", "a", "map"], "versions": "nope"}})
        facts = MoreRegistries.cargo("demo", "1.0.0")
        assert facts == PackageFacts(name="demo", version="1.0.0")

    def test_an_unknown_crate_is_not_found(self, serve) -> None:
        serve({})
        with pytest.raises(PackageNotFound):
            MoreRegistries.cargo("nope", "1.0.0")


class TestRubyGems(RegistryFixtures):
    GEM = "https://rubygems.org/api/v1/gems/demo.json"
    VERSIONS = "https://rubygems.org/api/v1/versions/demo.json"

    def answers(self, versions: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            self.GEM: {"version": "2.1.0", "source_code_uri": "https://github.com/o/demo"},
            self.VERSIONS: versions,
        }

    def test_a_version_the_gem_no_longer_lists_was_withdrawn(self, serve) -> None:
        serve(self.answers([{"number": "2.1.0", "platform": "ruby", "sha": SHA256}]))
        facts = MoreRegistries.rubygems("demo", "1.6.13")
        assert facts.yanked and "no longer listed" in (facts.yanked_reason or "")
        assert facts.latest == "2.1.0" and facts.repository == "https://github.com/o/demo"

    def test_every_platform_build_of_the_version_contributes_a_digest(self, serve) -> None:
        serve(
            self.answers(
                [
                    {
                        "number": "1.0.0",
                        "platform": "ruby",
                        "sha": SHA256,
                        "created_at": "2021-02-01",
                    },
                    {
                        "number": "1.0.0",
                        "platform": "java",
                        "sha": "cd" * 32,
                        "created_at": "2021-01-01",
                    },
                    {
                        "number": "0.9.0",
                        "platform": "ruby",
                        "sha": "ef" * 32,
                        "created_at": "2020-01-01",
                    },
                ]
            )
        )
        facts = MoreRegistries.rubygems("demo", "1.0.0")
        assert not facts.yanked
        assert set(facts.digests) == {SHA256, "cd" * 32}
        assert facts.first_published == "2020-01-01" and facts.releases == 2

    def test_a_platform_qualified_pin_matches_its_build(self, serve) -> None:
        serve(self.answers([{"number": "1.0.0", "platform": "java", "sha": SHA256}]))
        facts = MoreRegistries.rubygems("demo", "1.0.0-java")
        assert not facts.yanked and facts.digests == (SHA256,)

    def test_no_version_asked_is_never_withdrawn(self, serve) -> None:
        serve(self.answers([]))
        assert not MoreRegistries.rubygems("demo", None).yanked


class TestNuGet(RegistryFixtures):
    INDEX = "https://api.nuget.org/v3/registration5-gz-semver2/demo.pkg/index.json"
    LEAF = "https://api.nuget.org/v3/catalog0/data/demo.pkg.1.0.0.json"

    @staticmethod
    def leaf(version: str, **extra: Any) -> dict[str, Any]:
        return {"catalogEntry": {"version": version, "published": "2022-01-01T00:00:00Z", **extra}}

    def test_an_unlisted_version_is_withdrawn_with_its_deprecation(self, serve) -> None:
        serve(
            {
                self.INDEX: {
                    "items": [
                        {
                            "items": [
                                self.leaf(
                                    "1.0.0",
                                    listed=False,
                                    deprecation={"reasons": ["CriticalBugs"]},
                                    **{"@id": self.LEAF},
                                ),
                                self.leaf("1.1.0"),
                                self.leaf("2.0.0-preview1"),
                            ]
                        }
                    ]
                },
                self.LEAF: {"packageHash": SHA512_B64, "packageHashAlgorithm": "SHA512"},
            }
        )
        facts = MoreRegistries.nuget("Demo.Pkg", "1.0.0")
        assert facts.yanked and "unlisted" in (facts.yanked_reason or "")
        assert "CriticalBugs" in (facts.yanked_reason or "")
        assert facts.digests == (f"sha512-{SHA512_B64}",)
        # The newest stable, listed version: not the preview and not the unlisted one.
        assert facts.latest == "1.1.0"

    def test_pages_are_fetched_when_the_index_does_not_inline_them(self, serve) -> None:
        page = "https://api.nuget.org/v3/registration5-gz-semver2/demo.pkg/page/1.0.0/2.0.0.json"
        served = serve(
            {self.INDEX: {"items": [{"@id": page}]}, page: {"items": [self.leaf("1.0.0")]}}
        )
        facts = MoreRegistries.nuget("Demo.Pkg", "1.0.0")
        assert not facts.yanked and page in served.asked

    def test_a_page_on_another_host_is_never_fetched(self, serve) -> None:
        served = serve({self.INDEX: {"items": [{"@id": "https://evil.example/page.json"}]}})
        with pytest.raises(RegistryError, match=r"outside api\.nuget\.org"):
            MoreRegistries.nuget("Demo.Pkg", "1.0.0")
        assert "https://evil.example/page.json" not in served.asked

    def test_a_catalog_leaf_on_another_host_is_never_fetched(self, serve) -> None:
        serve(
            {
                self.INDEX: {
                    "items": [{"items": [self.leaf("1.0.0", **{"@id": "http://api.nuget.org/x"})]}]
                }
            }
        )
        with pytest.raises(RegistryError, match=r"outside api\.nuget\.org"):
            MoreRegistries.nuget("Demo.Pkg", "1.0.0")

    def test_the_unlisted_placeholder_date_is_not_a_first_release(self, serve) -> None:
        serve(
            {
                self.INDEX: {
                    "items": [
                        {
                            "items": [
                                {
                                    "catalogEntry": {
                                        "version": "0.1.0",
                                        "published": "1900-01-01T00:00:00Z",
                                        "listed": False,
                                    }
                                },
                                self.leaf("1.0.0"),
                            ]
                        }
                    ]
                }
            }
        )
        assert MoreRegistries.nuget("Demo.Pkg", "1.0.0").first_published == "2022-01-01T00:00:00Z"

    def test_an_unknown_hash_algorithm_is_not_published_as_a_digest(self, serve) -> None:
        serve(
            {
                self.INDEX: {"items": [{"items": [self.leaf("1.0.0", **{"@id": self.LEAF})]}]},
                self.LEAF: {"packageHash": "abc", "packageHashAlgorithm": "MD4"},
            }
        )
        assert MoreRegistries.nuget("Demo.Pkg", "1.0.0").digests == ()


class TestGo(RegistryFixtures):
    def test_uppercase_is_escaped_the_way_the_proxy_requires(self) -> None:
        assert MoreRegistries.go_escape("github.com/Azure/SDK") == "github.com/!azure/!s!d!k"

    def test_retractions_single_ranged_and_in_blocks(self) -> None:
        go_mod = (
            "module example.com/m\n"
            "/* retract v9.9.9 in a comment */\n"
            "retract v1.0.1 // published by mistake\n"
            "retract (\n"
            "    v1.2.0\n"
            "    [v1.3.0, v1.3.5] // credential leak\n"
            ")\n"
        )
        found = MoreRegistries.retractions(go_mod)
        assert found == {
            "v1.0.1": "published by mistake",
            "v1.2.0": "",
            "v1.3.0..v1.3.5": "credential leak",
        }
        assert MoreRegistries.retracted("v1.0.1", found) == "published by mistake"
        assert MoreRegistries.retracted("v1.2.0", found) == "retracted by its author"
        assert MoreRegistries.retracted("v1.3.2", found) == "credential leak"
        assert MoreRegistries.retracted("v1.3.6", found) is None
        assert MoreRegistries.retracted("v9.9.9", found) is None

    def test_a_prerelease_sorts_before_its_release_inside_a_range(self) -> None:
        found = {"v1.3.0..v1.3.5": "x"}
        assert MoreRegistries.retracted("v1.3.0-rc.1", found) is None
        assert MoreRegistries.retracted("v1.3.5-rc.1", found) == "x"

    def test_a_version_that_is_not_semver_is_never_in_a_range(self) -> None:
        assert MoreRegistries.retracted("latest", {"v0.0.0..v9.9.9": "x"}) is None

    def test_facts_combine_the_proxy_the_latest_go_mod_and_the_checksum_database(
        self, serve
    ) -> None:
        name = "github.com/Owner/mod"
        root = "https://proxy.golang.org/github.com/!owner/mod"
        h1 = "h1:" + base64.b64encode(b"\x01" * 32).decode()
        h1_mod = "h1:" + base64.b64encode(b"\x02" * 32).decode()
        serve(
            {
                f"{root}/@v/list": "v1.0.0\nv1.1.0\n",
                f"{root}/@latest": {"Version": "v1.1.0"},
                f"{root}/@v/v1.1.0.mod": "module github.com/Owner/mod\nretract v1.0.0 // broken\n",
                "https://sum.golang.org/lookup/github.com/!owner/mod@v1.0.0": (
                    "123\n"
                    f"{name} v1.0.0 {h1}\n"
                    f"{name} v1.0.0/go.mod {h1_mod}\n"
                    f"github.com/other/mod v1.0.0 {h1}\n"
                    "\ngo.sum database tree\n"
                ),
            }
        )
        facts = MoreRegistries.gomod(name, "v1.0.0")
        assert facts.yanked and facts.yanked_reason == "broken"
        assert facts.latest == "v1.1.0" and facts.releases == 2
        assert facts.digests == (h1, h1_mod)
        assert facts.repository == "https://github.com/Owner/mod"

    def test_a_module_the_checksum_database_does_not_know_still_answers_the_rest(
        self, serve
    ) -> None:
        root = "https://proxy.golang.org/example.com/m"
        serve({f"{root}/@v/list": "v1.0.0\n", f"{root}/@latest": {"Version": "v1.0.0"}})
        facts = MoreRegistries.gomod("example.com/m", "v1.0.0")
        assert not facts.yanked and facts.digests == () and facts.repository is None


class TestMaven(RegistryFixtures):
    ROOT = "https://repo.maven.apache.org/maven2/org/demo/lib"
    METADATA = (
        "<metadata><versioning><latest>2.0.0</latest><release>1.9.0</release><versions>"
        "<version>1.0.0</version><version>1.9.0</version><version>2.0.0</version>"
        "</versions></versioning></metadata>"
    )

    def test_every_published_checksum_and_a_sigstore_bundle(self, serve) -> None:
        stem = f"{self.ROOT}/1.0.0/lib-1.0.0.jar"
        serve(
            {
                f"{self.ROOT}/maven-metadata.xml": self.METADATA,
                f"{stem}.sha256": f"{SHA256.upper()}  lib-1.0.0.jar\n",
                f"{stem}.sha1": "ab" * 20,
                f"{stem}.sigstore.json": {"mediaType": "application/vnd.dev.sigstore.bundle+json"},
            }
        )
        facts = MoreRegistries.maven("org.demo:lib", "1.0.0")
        assert facts.digests == (f"sha256:{SHA256}", f"sha1:{'ab' * 20}")
        assert facts.attested and facts.latest == "1.9.0" and facts.releases == 3
        assert not facts.yanked

    def test_an_unreachable_checksum_does_not_lose_the_others(self, serve) -> None:
        stem = f"{self.ROOT}/1.0.0/lib-1.0.0.jar"
        serve(
            {
                f"{self.ROOT}/maven-metadata.xml": self.METADATA,
                f"{stem}.sha512": RegistryError("HTTP 503"),
                f"{stem}.sha1": "ab" * 20,
            }
        )
        facts = MoreRegistries.maven("org.demo:lib", "1.0.0")
        assert facts.digests == (f"sha1:{'ab' * 20}",) and not facts.attested

    def test_a_version_central_does_not_list_asks_for_nothing_more(self, serve) -> None:
        served = serve({f"{self.ROOT}/maven-metadata.xml": self.METADATA})
        assert MoreRegistries.maven("org.demo:lib", "0.0.1").digests == ()
        assert served.asked == [f"{self.ROOT}/maven-metadata.xml"]

    @pytest.mark.parametrize(
        "name", ["lib", "org.demo:", ":lib", "org/../x:lib", "org.demo:lib/../../x"]
    )
    def test_a_name_that_is_not_a_coordinate_is_refused(self, name) -> None:
        with pytest.raises(RegistryError):
            MoreRegistries.maven(name, "1.0.0")

    def test_a_checksum_file_that_holds_no_digest_is_ignored(self, serve) -> None:
        stem = f"{self.ROOT}/1.0.0/lib-1.0.0.jar"
        serve(
            {
                f"{self.ROOT}/maven-metadata.xml": self.METADATA,
                f"{stem}.sha256": "<html>nope</html>",
            }
        )
        assert MoreRegistries.maven("org.demo:lib", "1.0.0").digests == ()


class TestPackagist(RegistryFixtures):
    URL = "https://repo.packagist.org/p2/acme/demo.json"

    def answers(self) -> dict[str, Any]:
        return {
            self.URL: {
                "packages": {
                    "acme/demo": [
                        {
                            "version": "2.0.0-beta1",
                            "version_normalized": "2.0.0.0-beta1",
                            "time": "2024-03-01",
                            "source": {"url": "https://github.com/acme/demo.git"},
                            "dist": {"shasum": ""},
                        },
                        {"version": "1.1.0", "version_normalized": "1.1.0.0", "time": "2024-01-01"},
                        {
                            "version": "v1.0.0",
                            "version_normalized": "1.0.0.0",
                            "time": "2023-01-01",
                            "dist": {"shasum": "ab" * 20},
                            "source": "__unset",
                        },
                    ]
                }
            }
        }

    def test_minified_versions_are_expanded_and_unset_removes_a_key(self) -> None:
        expanded = MoreRegistries.expand_minified([{"a": 1, "b": 2}, {"b": 3}, {"a": "__unset"}])
        assert expanded == [{"a": 1, "b": 2}, {"a": 1, "b": 3}, {"b": 3}]

    def test_a_listed_version_its_shasum_and_the_newest_stable(self, serve) -> None:
        serve(self.answers())
        facts = MoreRegistries.composer("acme/demo", "v1.0.0")
        assert not facts.yanked and facts.digests == ("ab" * 20,)
        assert facts.latest == "1.1.0" and facts.first_published == "2023-01-01"
        # `source` was unset on this version, so the newest version's repository is used.
        assert facts.repository == "https://github.com/acme/demo.git"

    def test_a_normalised_pin_matches(self, serve) -> None:
        serve(self.answers())
        assert not MoreRegistries.composer("acme/demo", "1.1.0.0").yanked

    def test_a_tag_that_is_gone_was_withdrawn(self, serve) -> None:
        serve(self.answers())
        facts = MoreRegistries.composer("acme/demo", "1.0.5")
        assert facts.yanked and facts.yanked_reason == "no longer published on Packagist"

    @pytest.mark.parametrize("version", ["dev-main", "1.x-dev", None])
    def test_a_development_branch_is_never_withdrawn(self, serve, version) -> None:
        serve(self.answers())
        assert not MoreRegistries.composer("acme/demo", version).yanked

    @pytest.mark.parametrize("name", ["demo", "acme/", "/demo", "acme/demo/extra", "acme/../x"])
    def test_a_name_that_is_not_vendor_and_package_is_refused(self, name) -> None:
        with pytest.raises(RegistryError):
            MoreRegistries.composer(name, "1.0.0")


class TestPub(RegistryFixtures):
    URL = "https://pub.dev/api/packages/demo"

    def test_a_retracted_version_and_its_archive_hash(self, serve) -> None:
        serve(
            {
                self.URL: {
                    "latest": {
                        "version": "1.2.0",
                        "pubspec": {"repository": "https://github.com/o/demo"},
                    },
                    "versions": [
                        {
                            "version": "1.0.0",
                            "retracted": True,
                            "archive_sha256": SHA256.upper(),
                            "published": "2023-01-01",
                        },
                        {
                            "version": "1.2.0",
                            "archive_sha256": "cd" * 32,
                            "published": "2024-01-01",
                        },
                    ],
                }
            }
        )
        facts = MoreRegistries.pub("demo", "1.0.0")
        assert facts.yanked and facts.yanked_reason == "retracted by its publisher"
        assert facts.digests == (f"sha256:{SHA256}",) and facts.latest == "1.2.0"
        assert (
            facts.repository == "https://github.com/o/demo"
            and facts.first_published == "2023-01-01"
        )

    def test_retracted_must_be_true_not_merely_present(self, serve) -> None:
        serve({self.URL: {"versions": [{"version": "1.0.0", "retracted": "yes"}]}})
        assert not MoreRegistries.pub("demo", "1.0.0").yanked


class TestHex(RegistryFixtures):
    URL = "https://hex.pm/api/packages/demo"

    def test_a_retired_release_carries_its_reason_and_the_outer_checksum(self, serve) -> None:
        serve(
            {
                self.URL: {
                    "retirements": {"1.0.0": {"reason": "security", "message": "CVE fix in 1.0.1"}},
                    "releases": [{"version": "1.0.1"}, {"version": "1.0.0"}],
                    "latest_stable_version": "1.0.1",
                    "meta": {"links": {"GitHub": "https://github.com/o/demo"}},
                    "inserted_at": "2019-01-01T00:00:00Z",
                },
                f"{self.URL}/releases/1.0.0": {"checksum": SHA256.upper()},
            }
        )
        facts = MoreRegistries.hex("demo", "1.0.0")
        assert facts.yanked and facts.yanked_reason == "security - CVE fix in 1.0.1"
        assert facts.digests == (f"sha256:{SHA256}",) and facts.latest == "1.0.1"
        assert facts.repository == "https://github.com/o/demo" and facts.releases == 2

    def test_a_version_hex_does_not_have_asks_for_no_release(self, serve) -> None:
        served = serve({self.URL: {"releases": [{"version": "1.0.1"}]}})
        facts = MoreRegistries.hex("demo", "0.0.1")
        assert facts.digests == () and not facts.yanked
        assert served.asked == [self.URL]

    def test_a_retirement_with_no_words_still_says_why(self, serve) -> None:
        serve({self.URL: {"retirements": {"1.0.0": {"reason": ""}}, "releases": []}})
        assert MoreRegistries.hex("demo", "1.0.0").yanked_reason == "retired by its owner"


class TestDigestsTheNewRegistriesPublish:
    def test_go_h1_hashes_compare_with_each_other(self) -> None:
        h1 = "h1:" + base64.b64encode(b"\x07" * 32).decode()
        assert RegistryEvidence._canonical_digest(h1) == ("h1", "07" * 32)

    def test_an_h1_that_is_not_a_sha256_is_not_a_digest(self) -> None:
        assert (
            RegistryEvidence._canonical_digest("h1:" + base64.b64encode(b"\x07" * 20).decode())
            is None
        )
        assert RegistryEvidence._canonical_digest("h1:not base64!") is None

    def test_nugets_bare_base64_content_hash_is_a_sha512(self) -> None:
        assert RegistryEvidence._canonical_digest(SHA512_B64) == ("sha512", bytes(range(64)).hex())

    def test_a_bare_base64_sha256_is_read_too(self) -> None:
        raw = bytes(range(32))
        assert RegistryEvidence._canonical_digest(base64.b64encode(raw).decode()) == (
            "sha256",
            raw.hex(),
        )

    def test_a_tagged_inner_hex_checksum_is_never_compared(self) -> None:
        assert RegistryEvidence._canonical_digest(f"hexinner:{SHA256}") is None


class TestTheDetectorAsksTheNewRegistries:
    @staticmethod
    def dependency(
        ecosystem: str, name: str, *, integrity: str | None = None, resolved: str | None = None
    ) -> Dependency:
        return Dependency(
            purl=f"pkg:{ecosystem}/{name}@1.0.0",
            ecosystem=ecosystem,
            name=name,
            version="1.0.0",
            direct=True,
            scope=Scope.RUNTIME,
            integrity=integrity,
            resolved_from=resolved,
        )

    @staticmethod
    def ids(dependency: Dependency) -> list[str]:
        ctx = ScanContext(
            config=Config.default(), rules=RuleSet(RuleLoader.load_builtin()), offline=False
        )
        return [
            f.rule_id
            for f in RegistryDetector().inspect(GraphUnit(dependencies=(dependency,)), ctx)
        ]

    @pytest.fixture
    def answer(self, monkeypatch):
        def install(facts: PackageFacts | Exception) -> None:
            def fake(ecosystem: str, name: str, version: str | None):
                if isinstance(facts, Exception):
                    raise facts
                return facts

            monkeypatch.setattr("cordon_scanner.intel.registry_client.RegistryClient.facts", fake)

        return install

    def test_every_new_ecosystem_is_asked(self) -> None:
        assert {
            "cargo",
            "rubygems",
            "nuget",
            "gomod",
            "maven",
            "gradle",
            "composer",
            "pub",
            "hex",
        } <= REGISTRY_ECOSYSTEMS

    @pytest.mark.parametrize("ecosystem", ["cargo", "nuget", "gomod", "maven", "pub", "hex"])
    def test_none_of_them_is_reported_as_having_no_registry(self, answer, ecosystem) -> None:
        answer(PackageFacts(name="x", version="1.0.0"))
        assert "OPERATIONAL.REGISTRY.NO_SOURCE.001" not in self.ids(self.dependency(ecosystem, "x"))

    def test_a_yanked_crate_is_reported(self, answer) -> None:
        answer(PackageFacts(name="x", version="1.0.0", yanked=True))
        assert "SUSPECT.DEPENDENCY.YANKED.001" in self.ids(self.dependency("cargo", "x"))

    def test_a_go_sum_hash_the_checksum_database_contradicts_is_critical(self, answer) -> None:
        mine = "h1:" + base64.b64encode(b"\x01" * 32).decode()
        theirs = "h1:" + base64.b64encode(b"\x02" * 32).decode()
        answer(PackageFacts(name="m", version="1.0.0", digests=(theirs,)))
        assert "SUSPECT.PROVENANCE.MISMATCH.001" in self.ids(
            self.dependency("gomod", "m", integrity=mine)
        )

    def test_a_go_sum_hash_the_checksum_database_agrees_with_is_silent(self, answer) -> None:
        mine = "h1:" + base64.b64encode(b"\x01" * 32).decode()
        answer(
            PackageFacts(
                name="m",
                version="1.0.0",
                digests=(mine, "h1:" + base64.b64encode(b"\x02" * 32).decode()),
            )
        )
        assert "SUSPECT.PROVENANCE.MISMATCH.001" not in self.ids(
            self.dependency("gomod", "m", integrity=mine)
        )

    def test_a_nuget_content_hash_matching_the_catalog_is_silent(self, answer) -> None:
        answer(PackageFacts(name="p", version="1.0.0", digests=(f"sha512-{SHA512_B64}",)))
        assert "SUSPECT.PROVENANCE.MISMATCH.001" not in self.ids(
            self.dependency("nuget", "p", integrity=SHA512_B64)
        )

    @pytest.mark.parametrize("ecosystem", ["gomod", "maven", "composer"])
    def test_absence_is_not_dependency_confusion_where_names_are_owned(
        self, answer, ecosystem
    ) -> None:
        answer(PackageNotFound("no such package"))
        assert "SUSPECT.DEPENDENCY.UNREGISTERED.001" not in self.ids(
            self.dependency(ecosystem, "corp/internal")
        )

    @pytest.mark.parametrize("ecosystem", sorted(CONFUSABLE_ECOSYSTEMS))
    def test_absence_is_dependency_confusion_where_names_are_first_come(
        self, answer, ecosystem
    ) -> None:
        answer(PackageNotFound("no such package"))
        assert "SUSPECT.DEPENDENCY.UNREGISTERED.001" in self.ids(
            self.dependency(ecosystem, "corp-internal")
        )

    def test_a_crate_from_a_private_registry_is_not_confusion(self, answer) -> None:
        answer(PackageNotFound("no such package"))
        dependency = self.dependency(
            "cargo", "corp-internal", resolved="https://cargo.corp.example/api"
        )
        assert "SUSPECT.DEPENDENCY.UNREGISTERED.001" not in self.ids(dependency)

    @pytest.mark.parametrize("ecosystem", ["rubygems", "composer"])
    def test_absence_from_a_public_list_is_not_withdrawal_for_a_private_source(
        self, answer, ecosystem
    ) -> None:
        answer(PackageFacts(name="g", version="1.0.0", yanked=True))
        private = self.dependency(ecosystem, "g", resolved="https://gems.corp.example/g-1.0.0.gem")
        assert "SUSPECT.DEPENDENCY.YANKED.001" not in self.ids(private)

    @pytest.mark.parametrize(
        "resolved",
        [
            None,
            "https://rubygems.org/gems/g-1.0.0.gem",
            "https://api.github.com/repos/acme/g/zipball/abc",
        ],
    )
    def test_absence_from_a_public_list_is_withdrawal_for_a_public_source(
        self, answer, resolved
    ) -> None:
        answer(PackageFacts(name="g", version="1.0.0", yanked=True))
        public = self.dependency(
            "composer" if resolved and "github" in resolved else "rubygems", "g", resolved=resolved
        )
        assert "SUSPECT.DEPENDENCY.YANKED.001" in self.ids(public)

    def test_a_retired_hex_release_is_reported_whatever_its_source(self, answer) -> None:
        answer(PackageFacts(name="h", version="1.0.0", yanked=True, yanked_reason="security"))
        dependency = self.dependency("hex", "h", resolved="https://hex.corp.example/h")
        assert "SUSPECT.DEPENDENCY.YANKED.001" in self.ids(dependency)


class TestLockfilesRecordTheHashTheRegistryPublishes:
    @staticmethod
    def entries(path: str, text: str):
        ecosystem = EcosystemRegistry.get(EcosystemRegistry.lockfile_ecosystem(path) or "")
        assert ecosystem is not None
        return ecosystem.parse_lockfile(FileContent.from_bytes(path, text.encode())).entries

    def test_mix_lock_records_the_outer_checksum_past_the_dependency_list(self) -> None:
        inner, outer = "11" * 32, "22" * 32
        text = (
            "%{\n"
            f'  "plug": {{:hex, :plug, "1.15.3", "{inner}", [:mix], '
            '[{:mime, "~> 1.0 or ~> 2.0", [hex: :mime, repo: "hexpm", optional: false]}], '
            f'"hexpm", "{outer}"}},\n'
            "}\n"
        )
        (entry,) = self.entries("mix.lock", text)
        assert entry.name == "plug" and entry.version == "1.15.3"
        assert entry.integrity == f"sha256:{outer}"

    def test_an_old_mix_lock_with_only_the_inner_checksum_is_kept_but_never_compared(self) -> None:
        inner = "33" * 32
        (entry,) = self.entries(
            "mix.lock", f'%{{\n  "jason": {{:hex, :jason, "1.2.0", "{inner}", [:mix], []}},\n}}\n'
        )
        assert entry.integrity == f"hexinner:{inner}"
        assert RegistryEvidence._canonical_digest(entry.integrity) is None

    def test_pubspec_lock_records_the_archive_sha256(self) -> None:
        text = (
            "packages:\n"
            "  http:\n"
            '    dependency: "direct main"\n'
            "    description:\n"
            "      name: http\n"
            f'      sha256: "{SHA256.upper()}"\n'
            '      url: "https://pub.dev"\n'
            "    source: hosted\n"
            '    version: "1.2.0"\n'
        )
        (entry,) = self.entries("pubspec.lock", text)
        assert entry.integrity == f"sha256:{SHA256}"

    def test_a_pubspec_lock_without_a_hash_records_none(self) -> None:
        text = 'packages:\n  http:\n    description:\n      name: http\n      sha256: nothex\n    version: "1.0.0"\n'
        (entry,) = self.entries("pubspec.lock", text)
        assert entry.integrity is None
