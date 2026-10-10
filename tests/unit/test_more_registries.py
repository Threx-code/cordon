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
from typing import Any, ClassVar

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
            # The operating system's packages: matched against distribution advisories, no registry.
            MoreRegistries.facts("deb", "openssl", "3.0.15-1")

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


class TestCocoaPodsTrunk(RegistryFixtures):
    """Trunk's CDN: the shard's version listing, and each version's podspec JSON, whose SHA-1 is
    what a Podfile.lock's SPEC CHECKSUMS records."""

    PODSPEC = b'{"name": "Alamofire", "version": "5.9.1", "deprecated": true, "deprecated_in_favor_of": "Alamofire2"}'

    def urls(self, name: str = "Alamofire", version: str = "5.9.1") -> tuple[str, str]:
        a, b, c = MoreRegistries.cocoapods_shard(name)
        base = "https://cdn.cocoapods.org"
        return (
            f"{base}/all_pods_versions_{a}_{b}_{c}.txt",
            f"{base}/Specs/{a}/{b}/{c}/{name}/{version}/{name}.podspec.json",
        )

    @pytest.mark.conformance("cocoapods", "UNI-16", "UNI-22")
    def test_the_podspec_checksum_versions_and_deprecation(self, serve) -> None:
        import hashlib

        listing, podspec = self.urls()
        served = serve({listing: "Other/1.0\nAlamofire/5.8.0/5.9.1\n", podspec: self.PODSPEC})
        facts = MoreRegistries.cocoapods("Alamofire", "5.9.1")
        assert facts.digests == (
            f"sha1:{hashlib.sha1(self.PODSPEC, usedforsecurity=False).hexdigest()}",
        )
        assert facts.releases == 2 and facts.latest == "5.9.1" and not facts.yanked
        assert facts.deprecated == "deprecated in favour of Alamofire2"
        assert served.asked == [listing, podspec]

    @pytest.mark.conformance("cocoapods", "UNI-16")
    def test_a_version_trunk_no_longer_lists_was_deleted(self, serve) -> None:
        listing, _ = self.urls()
        serve({listing: "Alamofire/5.8.0\n"})
        assert MoreRegistries.cocoapods("Alamofire", "5.9.1").yanked

    @pytest.mark.conformance("cocoapods", "UNI-16")
    def test_a_pod_trunk_does_not_have_is_not_found(self, serve) -> None:
        listing, _ = self.urls("NoSuchPodAnywhere")
        serve({listing: "Other/1.0\n"})
        with pytest.raises(PackageNotFound):
            MoreRegistries.cocoapods("NoSuchPodAnywhere", "1.0.0")

    @pytest.mark.conformance("cocoapods", "UNI-22")
    def test_a_name_that_is_not_a_pod_name_is_never_requested(self, serve) -> None:
        served = serve({})
        with pytest.raises(RegistryError):
            MoreRegistries.cocoapods("../../etc", "1.0")
        assert served.asked == []


class TestCran(RegistryFixtures):
    URL = "https://crandb.r-pkg.org/jsonlite/all"
    DOCUMENT: ClassVar[dict[str, Any]] = {
        "name": "jsonlite",
        "versions": {"1.8.9": {}, "2.0.0": {}},
        "timeline": {"1.8.9": "2024-09-20T09:30:02+00:00", "2.0.0": "2025-03-27T05:40:02+00:00"},
        "latest": {"Version": "2.0.0"},
        "archived": False,
    }

    @pytest.mark.conformance("cran", "UNI-16", "UNI-22")
    def test_versions_dates_and_the_latest(self, serve) -> None:
        serve({self.URL: self.DOCUMENT})
        facts = MoreRegistries.cran("jsonlite", "1.8.9")
        assert facts.releases == 2 and facts.latest == "2.0.0" and not facts.yanked
        assert facts.first_published == "2024-09-20T09:30:02+00:00" and facts.digests == ()

    @pytest.mark.conformance("cran", "UNI-16")
    def test_an_archived_package_is_withdrawn(self, serve) -> None:
        serve({self.URL: {**self.DOCUMENT, "archived": True}})
        facts = MoreRegistries.cran("jsonlite", "2.0.0")
        assert facts.yanked and facts.yanked_reason == "archived by CRAN"

    @pytest.mark.conformance("cran", "UNI-16")
    def test_a_version_cran_never_published(self, serve) -> None:
        serve({self.URL: self.DOCUMENT})
        facts = MoreRegistries.cran("jsonlite", "9.9.9")
        assert facts.yanked and facts.yanked_reason == "not a version CRAN published"

    @pytest.mark.conformance("cran", "UNI-16")
    def test_a_version_is_compared_as_r_compares_it(self, serve) -> None:
        # R reads `1.2.16` and `1.2-16` as one version; a renv.lock pinning AER `1.2.16` was
        # reported withdrawn. Ordered by R too: 1.2-17 is newer than 1.2-9.
        url = "https://crandb.r-pkg.org/AER/all"
        serve({url: {"versions": {"1.2-9": {}, "1.2-16": {}, "1.2-17": {}}, "archived": False}})
        facts = MoreRegistries.cran("AER", "1.2.16")
        assert not facts.yanked and facts.latest == "1.2-17"
        assert MoreRegistries.cran("AER", "1.2.15").yanked

    @pytest.mark.conformance("cran", "UNI-22")
    def test_an_unreachable_registry_and_a_hostile_name(self, serve) -> None:
        serve({self.URL: RegistryError("connection timed out")})
        with pytest.raises(RegistryError):
            MoreRegistries.cran("jsonlite", "2.0.0")
        with pytest.raises(RegistryError):
            MoreRegistries.cran("../../etc/passwd", "1")


class TestHackage(RegistryFixtures):
    BASE = "https://hackage.haskell.org/package"
    REVISION = "2ba66a092a32593880a87fb00f3213762d7bca65a687d45965778deb8694c5d1"

    def answers(self, **overrides: Any) -> dict[str, Any]:
        return {
            f"{self.BASE}/acme-missiles/preferred": {
                "normal-version": ["0.3", "0.2"],
                "deprecated-version": ["0.1"],
            },
            f"{self.BASE}/acme-missiles/deprecated": {"is-deprecated": False, "in-favour-of": []},
            f"{self.BASE}/acme-missiles-0.3/revisions/": [
                {"number": 0, "sha256": self.REVISION, "time": "2012-04-15T04:08:20Z", "user": "u"}
            ],
            f"{self.BASE}/acme-missiles-0.1/revisions/": [],
            **overrides,
        }

    @pytest.mark.conformance("hackage", "UNI-16", "UNI-22", "hackage.revisions")
    def test_revision_hashes_and_the_latest(self, serve) -> None:
        serve(self.answers())
        facts = MoreRegistries.hackage("acme-missiles", "0.3")
        # The cabal-file revision hash Stack's lock pins (`@sha256:...`).
        assert facts.digests == (f"sha256:{self.REVISION}",)
        assert facts.latest == "0.3" and not facts.yanked and facts.releases == 3

    @pytest.mark.conformance("hackage", "UNI-16")
    def test_a_deprecated_version_and_package(self, serve) -> None:
        serve(
            self.answers(
                **{
                    f"{self.BASE}/acme-missiles/deprecated": {
                        "is-deprecated": True,
                        "in-favour-of": ["acme-rockets"],
                    }
                }
            )
        )
        facts = MoreRegistries.hackage("acme-missiles", "0.1")
        assert (
            facts.yanked
            and facts.yanked_reason == "deprecated by its maintainer: the solver avoids it"
        )
        assert facts.deprecated == "deprecated on Hackage in favour of acme-rockets"

    @pytest.mark.conformance("hackage", "UNI-16")
    def test_a_version_hackage_never_published(self, serve) -> None:
        serve(self.answers())
        facts = MoreRegistries.hackage("acme-missiles", "9.9")
        assert (
            facts.yanked
            and facts.yanked_reason == "not a version Hackage published"
            and facts.digests == ()
        )

    @pytest.mark.conformance("hackage", "UNI-22")
    def test_an_unreachable_registry_and_hostile_coordinates(self, serve) -> None:
        serve({f"{self.BASE}/acme-missiles/preferred": RegistryError("connection timed out")})
        with pytest.raises(RegistryError):
            MoreRegistries.hackage("acme-missiles", "0.3")
        with pytest.raises(RegistryError):
            MoreRegistries.hackage("../../etc/passwd", "1")
        serve(self.answers())
        with pytest.raises(RegistryError):
            MoreRegistries.hackage("acme-missiles", "0.3/../../x")


class TestJuliaGeneral(RegistryFixtures):
    BASE = "https://raw.githubusercontent.com/JuliaRegistries/General/master/J/JSON3"
    PACKAGE = 'name = "JSON3"\nuuid = "0f8b85d8-7281-11e9-16c2-39a750bddbf1"\nrepo = "https://github.com/quinnj/JSON3.jl.git"\n'
    VERSIONS = (
        '["1.14.2"]\ngit-tree-sha1 = "196b41e5a854b387d99e5ede2de3fcb4d0422aae"\n\n'
        '["1.14.3"]\ngit-tree-sha1 = "411eccfe8aba0814ffa0fdf4860913ed09c34975"\n\n'
        '["1.15.0"]\ngit-tree-sha1 = "0000000000000000000000000000000000000001"\nyanked = true\n'
    )

    @pytest.mark.conformance("julia", "UNI-16", "UNI-22")
    def test_tree_hash_repository_and_latest(self, serve) -> None:
        serve(
            {f"{self.BASE}/Package.toml": self.PACKAGE, f"{self.BASE}/Versions.toml": self.VERSIONS}
        )
        facts = MoreRegistries.julia("JSON3", "1.14.3")
        # The tree a manifest's git-tree-sha1 pins.
        assert facts.digests == ("git-tree-sha1:411eccfe8aba0814ffa0fdf4860913ed09c34975",)
        assert facts.repository == "https://github.com/quinnj/JSON3.jl.git"
        assert facts.latest == "1.14.3" and not facts.yanked and facts.deprecated is None

    @pytest.mark.conformance("julia", "UNI-16")
    def test_yanked_unknown_and_deprecated(self, serve) -> None:
        retired = (
            self.PACKAGE
            + '\n[metadata.deprecated]\nreason = "unmaintained"\nalternative = "JSON"\n'
        )
        serve({f"{self.BASE}/Package.toml": retired, f"{self.BASE}/Versions.toml": self.VERSIONS})
        assert (
            MoreRegistries.julia("JSON3", "1.15.0").yanked_reason
            == "yanked from the General registry"
        )
        assert (
            MoreRegistries.julia("JSON3", "9.9.9").yanked_reason
            == "not a version the General registry holds"
        )
        assert (
            MoreRegistries.julia("JSON3", "1.14.3").deprecated
            == "deprecated in the General registry in favour of JSON"
        )

    @pytest.mark.conformance("julia", "UNI-22")
    def test_unreachable_unreadable_and_hostile(self, serve) -> None:
        serve({f"{self.BASE}/Package.toml": RegistryError("connection reset")})
        with pytest.raises(RegistryError):
            MoreRegistries.julia("JSON3", "1.14.3")
        serve(
            {
                f"{self.BASE}/Package.toml": "name = [unterminated",
                f"{self.BASE}/Versions.toml": self.VERSIONS,
            }
        )
        with pytest.raises(RegistryError):
            MoreRegistries.julia("JSON3", "1.14.3")
        with pytest.raises(RegistryError):
            MoreRegistries.julia("../../x", "1")


class TestOpamRepository(RegistryFixtures):
    RAW = "https://raw.githubusercontent.com/ocaml/opam-repository/master/packages/fmt"
    SITE = "https://opam.ocaml.org/packages/fmt/"
    SHA512 = "3f40155fc6a7315202e410585964307d63416c8001fd243667ed9d8d1a02b67deecacb25e9c2feb409c537bbdfb7817d91168de4ddd643532ff51d6c1c696a4a"
    OPAM = (
        'opam-version: "2.0"\ndev-repo: "git+https://erratique.ch/repos/fmt.git"\n'
        'url {\n  src: "https://erratique.ch/software/fmt/releases/fmt-0.11.0.tbz"\n'
        f'  checksum:\n    "sha512={SHA512}"\n}}\n'
    )

    @pytest.mark.conformance("opam", "UNI-16", "UNI-22", "opam.repositories")
    def test_checksum_and_repository(self, serve) -> None:
        serve({f"{self.RAW}/fmt.0.11.0/opam": self.OPAM})
        facts = MoreRegistries.opam("fmt", "0.11.0")
        # What dune's lock records for the archive.
        assert facts.digests == (f"sha512:{self.SHA512}",)
        assert facts.repository == "git+https://erratique.ch/repos/fmt.git" and not facts.yanked

    @pytest.mark.conformance("opam", "UNI-16")
    def test_flags_removed_versions_and_unknown_packages(self, serve) -> None:
        serve(
            {
                f"{self.RAW}/fmt.0.11.0/opam": self.OPAM + "flags: [avoid-version deprecated]\n",
                self.SITE: "<html></html>",
            }
        )
        flagged = MoreRegistries.opam("fmt", "0.11.0")
        assert flagged.yanked_reason == "flagged avoid-version: the solver avoids it"
        assert flagged.deprecated == "deprecated in opam-repository"
        assert (
            MoreRegistries.opam("fmt", "0.0.1").yanked_reason
            == "not a version opam-repository holds"
        )
        serve({})
        with pytest.raises(PackageNotFound):
            MoreRegistries.opam("fmt", "0.0.1")

    @pytest.mark.conformance("opam", "UNI-22")
    def test_unreachable_unreadable_and_hostile(self, serve) -> None:
        serve({f"{self.RAW}/fmt.0.11.0/opam": RegistryError("connection reset")})
        with pytest.raises(RegistryError):
            MoreRegistries.opam("fmt", "0.11.0")
        serve({f"{self.RAW}/fmt.0.11.0/opam": 'depends: ["unterminated'})
        with pytest.raises(RegistryError):
            MoreRegistries.opam("fmt", "0.11.0")
        with pytest.raises(RegistryError):
            MoreRegistries.opam("../../x", "1")
        with pytest.raises(RegistryError):
            MoreRegistries.opam("fmt", "1/../../x")


class TestConanCenter(RegistryFixtures):
    BASE = "https://center2.conan.io/v2/conans"
    SEARCH: ClassVar[dict[str, Any]] = {
        "results": ["zlib/1.2.11@_/_", "zlib/1.3.1@_/_", "zlib/1.3@_/_", "zlib-ng/2.2.1@_/_"]
    }
    REVISIONS: ClassVar[dict[str, Any]] = {
        "reference": "zlib/1.3.1@_/_",
        "revisions": [
            {
                "revision": "cac0f6daea041b0ccf42934163defb20",
                "time": "2025-12-09T12:51:39.337+0000",
            },
            {
                "revision": "b8bc2603263cf7eccbd6e17e66b0ed76",
                "time": "2024-12-11T16:57:24.862+0000",
            },
        ],
    }

    @pytest.mark.conformance("conan", "UNI-16", "UNI-22", "conan.revisions")
    def test_recipe_revisions_and_latest(self, serve) -> None:
        serve(
            {
                f"{self.BASE}/search?q=zlib": self.SEARCH,
                f"{self.BASE}/zlib/1.3.1/_/_/revisions": self.REVISIONS,
            }
        )
        facts = MoreRegistries.conan("zlib", "1.3.1")
        # Every revision of the version: a lock may pin any of them.
        assert facts.digests == (
            "md5:cac0f6daea041b0ccf42934163defb20",
            "md5:b8bc2603263cf7eccbd6e17e66b0ed76",
        )
        # zlib-ng is another recipe, not a version of zlib.
        assert facts.latest == "1.3.1" and facts.releases == 3 and not facts.yanked

    @pytest.mark.conformance("conan", "UNI-16")
    def test_a_version_and_a_recipe_conancenter_lacks(self, serve) -> None:
        serve({f"{self.BASE}/search?q=zlib": self.SEARCH})
        assert (
            MoreRegistries.conan("zlib", "1.0.0").yanked_reason == "not a version ConanCenter holds"
        )
        serve({f"{self.BASE}/search?q=acme-internal": {"results": []}})
        with pytest.raises(PackageNotFound):
            MoreRegistries.conan("acme-internal", "1.0")

    @pytest.mark.conformance("conan", "UNI-22")
    def test_unreachable_and_hostile(self, serve) -> None:
        serve({f"{self.BASE}/search?q=zlib": RegistryError("connection reset")})
        with pytest.raises(RegistryError):
            MoreRegistries.conan("zlib", "1.3.1")
        with pytest.raises(RegistryError):
            MoreRegistries.conan("../../x", "1")
        serve({f"{self.BASE}/search?q=zlib": self.SEARCH})
        with pytest.raises(RegistryError):
            MoreRegistries.conan("zlib", "1.3.1/../../x")


class TestVcpkgRegistry(RegistryFixtures):
    URL = "https://raw.githubusercontent.com/microsoft/vcpkg/master/versions/f-/fmt.json"
    DOCUMENT: ClassVar[dict[str, Any]] = {
        "versions": [
            {
                "git-tree": "7ca0b8c0026883daf28a0db75f6b4964bae2979a",
                "version": "12.2.0",
                "port-version": 1,
            },
            {
                "git-tree": "823af43db9df2c4be15c4331b36b3cc419afa02c",
                "version": "12.2.0",
                "port-version": 0,
            },
            {
                "git-tree": "936231a2c765082457d348a8781ea9d3610eb331",
                "version": "12.1.0",
                "port-version": 0,
            },
        ]
    }

    @pytest.mark.conformance("vcpkg", "UNI-16", "UNI-22", "vcpkg.port-versions")
    def test_git_trees_per_port_version_and_latest(self, serve) -> None:
        serve({self.URL: self.DOCUMENT})
        facts = MoreRegistries.vcpkg("fmt", "12.2.0")
        # Both port-versions of 12.2.0: each a different git-tree of the port.
        assert facts.digests == (
            "git-tree-sha1:7ca0b8c0026883daf28a0db75f6b4964bae2979a",
            "git-tree-sha1:823af43db9df2c4be15c4331b36b3cc419afa02c",
        )
        assert facts.latest == "12.2.0" and facts.releases == 2 and not facts.yanked

    @pytest.mark.conformance("vcpkg", "UNI-16")
    def test_a_version_and_a_port_the_registry_lacks(self, serve) -> None:
        serve({self.URL: self.DOCUMENT})
        assert (
            MoreRegistries.vcpkg("fmt", "9.0.0").yanked_reason
            == "not a version the vcpkg registry holds"
        )
        with pytest.raises(PackageNotFound):
            MoreRegistries.vcpkg("acme-internal", "1.0")

    @pytest.mark.conformance("vcpkg", "UNI-22")
    def test_unreachable_and_hostile(self, serve) -> None:
        serve({self.URL: RegistryError("connection reset")})
        with pytest.raises(RegistryError):
            MoreRegistries.vcpkg("fmt", "12.2.0")
        with pytest.raises(RegistryError):
            MoreRegistries.vcpkg("../../x", "1")


class TestActionTags(RegistryFixtures):
    URL = "https://github.com/actions/checkout.git/info/refs?service=git-upload-pack"
    COMMIT = "3d3c42e5aac5ba805825da76410c181273ba90b1"

    @staticmethod
    def advertisement(*lines: str) -> bytes:
        def pkt(text: str) -> bytes:
            return f"{len(text) + 5:04x}{text}\n".encode()

        return (
            pkt("# service=git-upload-pack")
            + b"0000"
            + b"".join(pkt(line) for line in lines)
            + b"0000"
        )

    def refs(self) -> bytes:
        return self.advertisement(
            "59f548e57e544e1ff5a4c46bf1e1b8685f8e4a348a HEAD\0multi_ack thin-pack",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa refs/tags/v7.0.1",
            f"{self.COMMIT} refs/tags/v7.0.1^{{}}",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb refs/tags/v7",
            "cccccccccccccccccccccccccccccccccccccccc refs/tags/v6.0.2",
        )

    @pytest.mark.conformance("actions", "UNI-16", "UNI-22", "actions.sha-pinning")
    def test_the_commit_a_release_tag_names(self, serve) -> None:
        serve({self.URL: self.refs()})
        facts = MoreRegistries.actions("actions/checkout", "7.0.1")
        # The annotated tag peeled to its commit: what a SHA pin with `# v7.0.1` must equal.
        assert facts.digests == (self.COMMIT,)
        assert facts.latest == "7.0.1" and facts.releases == 2 and not facts.yanked

    @pytest.mark.conformance("actions", "UNI-16")
    def test_a_release_no_tag_names_and_a_missing_repository(self, serve) -> None:
        serve({self.URL: self.refs()})
        assert (
            MoreRegistries.actions("actions/checkout", "9.9.9").yanked_reason
            == "no tag of the repository names this release"
        )
        serve(
            {
                "https://github.com/acme/gone.git/info/refs?service=git-upload-pack": RegistryError(
                    "HTTP 401 from github.com"
                )
            }
        )
        with pytest.raises(PackageNotFound):
            MoreRegistries.actions("acme/gone", "1.0.0")

    @pytest.mark.conformance("actions", "UNI-22")
    def test_unreachable_unreadable_and_hostile(self, serve) -> None:
        serve({self.URL: RegistryError("connection reset")})
        with pytest.raises(RegistryError):
            MoreRegistries.actions("actions/checkout", "7.0.1")
        serve({self.URL: b"zzzz-not-pkt-lines"})
        with pytest.raises(RegistryError):
            MoreRegistries.actions("actions/checkout", "7.0.1")
        with pytest.raises(RegistryError):
            MoreRegistries.actions("../../etc/passwd", "1")


class TestGalaxy(RegistryFixtures):
    INDEX = "https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections/index/ansible/posix/"
    SHA = "6dc970c9350e7c54e628dc0704631a41ebfd5056b6ab05a566155d8c999217e9"

    def collection(self, **overrides: Any) -> dict[str, Any]:
        return {
            self.INDEX: {
                "namespace": "ansible",
                "name": "posix",
                "deprecated": False,
                "highest_version": {"version": "2.2.2"},
                "created_at": "2023-05-08T20:27:28Z",
                "updated_at": "2026-07-13T02:34:05Z",
            },
            f"{self.INDEX}versions/1.5.4/": {
                "version": "1.5.4",
                "artifact": {"filename": "ansible-posix-1.5.4.tar.gz", "sha256": self.SHA},
            },
            **overrides,
        }

    @pytest.mark.conformance("ansible", "UNI-16", "UNI-22", "ansible.identity")
    def test_a_collection_version_and_its_artefact(self, serve) -> None:
        serve(self.collection())
        facts = MoreRegistries.ansible("ansible.posix", "1.5.4")
        assert (
            facts.digests == (f"sha256:{self.SHA}",)
            and facts.latest == "2.2.2"
            and not facts.yanked
        )

    @pytest.mark.conformance("ansible", "UNI-16")
    def test_a_deprecated_collection_and_a_missing_version(self, serve) -> None:
        index = self.collection()[self.INDEX]
        serve(self.collection(**{self.INDEX: {**index, "deprecated": True}}))
        assert MoreRegistries.ansible("ansible.posix", "1.5.4").deprecated == "deprecated on Galaxy"
        assert (
            MoreRegistries.ansible("ansible.posix", "0.0.1").yanked_reason
            == "not a version Galaxy holds"
        )

    @pytest.mark.conformance("ansible", "UNI-16", "ansible.collections-roles")
    def test_a_role_when_no_collection_has_the_name(self, serve) -> None:
        serve(
            {
                "https://galaxy.ansible.com/api/v1/roles/?owner__username=geerlingguy&name=docker": {
                    "results": [
                        {
                            "github_user": "geerlingguy",
                            "github_repo": "ansible-role-docker",
                            "summary_fields": {"versions": [{"name": "7.4.1"}, {"name": "7.4.0"}]},
                        }
                    ]
                }
            }
        )
        facts = MoreRegistries.ansible("geerlingguy.docker", "7.4.1")
        assert (
            facts.latest == "7.4.1"
            and facts.repository == "https://github.com/geerlingguy/ansible-role-docker"
        )
        assert MoreRegistries.ansible("geerlingguy.docker", "1.0.0").yanked
        serve(
            {
                "https://galaxy.ansible.com/api/v1/roles/?owner__username=acme&name=gone": {
                    "results": []
                }
            }
        )
        with pytest.raises(PackageNotFound):
            MoreRegistries.ansible("acme.gone", "1.0")

    @pytest.mark.conformance("ansible", "UNI-22")
    def test_unreachable_and_hostile(self, serve) -> None:
        serve({self.INDEX: RegistryError("connection reset")})
        with pytest.raises(RegistryError):
            MoreRegistries.ansible("ansible.posix", "1.5.4")
        with pytest.raises(RegistryError):
            MoreRegistries.ansible("../../x", "1")
        with pytest.raises(RegistryError):
            MoreRegistries.ansible("ansible.posix", "1/../../x")


class TestTerraformRegistry(RegistryFixtures):
    BASE = "https://registry.terraform.io/v1/providers/hashicorp/null"
    LINUX = "d2855b922ea345dbd89ea287e4c6c4757e38bc0aaffeb2b79aa0b8004f9c53ff"
    DARWIN = "10ec43b8b7b18d5639238c7fb9e111f6a4b038523dd66c7a426bf27b25fa4c08"
    VERSIONS: ClassVar[dict[str, Any]] = {
        "versions": [
            {
                "version": "3.3.2",
                "platforms": [{"os": "linux", "arch": "amd64"}, {"os": "darwin", "arch": "arm64"}],
            },
            {"version": "3.2.4", "platforms": [{"os": "linux", "arch": "amd64"}]},
        ]
    }

    def download(self, os_name: str, arch: str, shasum: str) -> dict[str, Any]:
        return {
            "os": os_name,
            "arch": arch,
            "shasum": shasum,
            "shasums_url": "https://releases.hashicorp.com/terraform-provider-null/3.3.2/terraform-provider-null_3.3.2_SHA256SUMS",
        }

    @pytest.mark.conformance("terraform", "UNI-16", "UNI-22", "terraform.hashes")
    def test_every_platforms_zip_hash(self, serve) -> None:
        serve(
            {
                f"{self.BASE}/versions": self.VERSIONS,
                f"{self.BASE}/3.3.2/download/linux/amd64": self.download(
                    "linux", "amd64", self.LINUX
                ),
                "https://releases.hashicorp.com/terraform-provider-null/3.3.2/terraform-provider-null_3.3.2_SHA256SUMS": f"{self.LINUX}  terraform-provider-null_3.3.2_linux_amd64.zip\n{self.DARWIN}  terraform-provider-null_3.3.2_darwin_arm64.zip\n",
            }
        )
        facts = MoreRegistries.terraform("hashicorp/null", "3.3.2")
        assert set(facts.digests) == {f"sha256:{self.LINUX}", f"sha256:{self.DARWIN}"}
        assert facts.latest == "3.3.2" and not facts.yanked

    @pytest.mark.conformance("terraform", "UNI-16", "UNI-22")
    def test_platform_by_platform_when_the_sums_file_is_out_of_reach(self, serve) -> None:
        serve(
            {
                f"{self.BASE}/versions": self.VERSIONS,
                f"{self.BASE}/3.3.2/download/linux/amd64": self.download(
                    "linux", "amd64", self.LINUX
                ),
                f"{self.BASE}/3.3.2/download/darwin/arm64": self.download(
                    "darwin", "arm64", self.DARWIN
                ),
            }
        )
        # Never one platform's hash alone: every other platform's would read as a mismatch.
        assert set(MoreRegistries.terraform("hashicorp/null", "3.3.2").digests) == {
            f"sha256:{self.LINUX}",
            f"sha256:{self.DARWIN}",
        }

    @pytest.mark.conformance("terraform", "UNI-16", "terraform.modules")
    def test_a_module_and_a_missing_version(self, serve) -> None:
        serve(
            {
                "https://registry.terraform.io/v1/modules/cloudposse/label/null/versions": {
                    "modules": [
                        {
                            "versions": [
                                {"version": "0.25.0", "deprecation": None},
                                {"version": "0.24.1", "deprecation": {"reason": "use 0.25"}},
                            ]
                        }
                    ]
                },
                f"{self.BASE}/versions": self.VERSIONS,
            }
        )
        assert MoreRegistries.terraform("cloudposse/label/null", "0.25.0").latest == "0.25.0"
        assert (
            MoreRegistries.terraform("cloudposse/label/null", "0.24.1").deprecated
            == "deprecated on the registry: use 0.25"
        )
        assert (
            MoreRegistries.terraform("hashicorp/null", "9.9.9").yanked_reason
            == "not a version the registry holds"
        )

    @pytest.mark.conformance("terraform", "UNI-22")
    def test_unreachable_and_hostile(self, serve) -> None:
        serve({f"{self.BASE}/versions": RegistryError("connection reset")})
        with pytest.raises(RegistryError):
            MoreRegistries.terraform("hashicorp/null", "3.3.2")
        with pytest.raises(RegistryError):
            MoreRegistries.terraform("../../etc/passwd", "1")
        with pytest.raises(RegistryError):
            MoreRegistries.terraform("hashicorp/null", "1/../../x")


class TestHelmRepositories(RegistryFixtures):
    REPO = "https://prometheus-community.github.io/helm-charts"
    DIGEST = "1e2f3a4b5c6d7e8f901a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70"
    INDEX = (
        "apiVersion: v1\nentries:\n  prometheus-node-exporter:\n"
        "    - name: prometheus-node-exporter\n      version: 4.59.0\n"
        f"      digest: {DIGEST}\n"
        "      urls:\n        - https://example.invalid/prometheus-node-exporter-4.59.0.tgz\n"
        "    - name: prometheus-node-exporter\n      version: 4.58.0\n      deprecated: true\n"
        f"      digest: {'0' * 64}\n"
    )

    @pytest.mark.conformance("helm", "UNI-16", "UNI-22", "helm.dependencies")
    def test_the_repository_index(self, serve) -> None:
        serve({f"{self.REPO}/index.yaml": self.INDEX})
        facts = MoreRegistries.facts("helm", "prometheus-node-exporter", "4.59.0", self.REPO)
        # The archive's SHA-256: what a chart downloaded into charts/ is hashed to.
        assert (
            facts.digests == (f"sha256:{self.DIGEST}",)
            and facts.latest == "4.59.0"
            and not facts.yanked
        )
        assert (
            MoreRegistries.helm("prometheus-node-exporter", "4.58.0", self.REPO).deprecated
            == "deprecated in its repository"
        )
        assert MoreRegistries.helm("prometheus-node-exporter", "1.0.0", self.REPO).yanked

    @pytest.mark.conformance("helm", "UNI-16", "helm.local-oci")
    def test_an_oci_registry_behind_an_anonymous_token(self, monkeypatch) -> None:
        answers = {
            "https://registry.example.invalid/v2/charts/postgresql/tags/list": {
                "tags": ["15.5.38", "15.5.37"]
            },
            "https://registry.example.invalid/v2/charts/postgresql/manifests/15.5.38": {
                "layers": [
                    {
                        "mediaType": "application/vnd.cncf.helm.chart.content.v1.tar+gzip",
                        "digest": f"sha256:{self.DIGEST}",
                    }
                ]
            },
        }
        monkeypatch.setattr(MoreRegistries, "_oci", staticmethod(lambda url, accept: answers[url]))
        facts = MoreRegistries.helm(
            "postgresql", "15.5.38", "oci://registry.example.invalid/charts"
        )
        assert facts.digests == (f"sha256:{self.DIGEST}",) and facts.latest == "15.5.38"
        assert MoreRegistries.helm(
            "postgresql", "9.9.9", "oci://registry.example.invalid/charts"
        ).yanked

    def test_an_oci_tag_holds_a_version_s_plus_as_an_underscore(self, monkeypatch) -> None:
        # helm pushes 1.0.0+build.1 as the tag 1.0.0_build.1; an older chart's layer has the
        # legacy media type.
        answers = {
            "https://registry.example.invalid/v2/charts/app/tags/list": {"tags": ["1.0.0_build.1"]},
            "https://registry.example.invalid/v2/charts/app/manifests/1.0.0_build.1": {
                "layers": [{"mediaType": "application/tar+gzip", "digest": f"sha256:{self.DIGEST}"}]
            },
        }
        monkeypatch.setattr(MoreRegistries, "_oci", staticmethod(lambda url, accept: answers[url]))
        facts = MoreRegistries.helm("app", "1.0.0+build.1", "oci://registry.example.invalid/charts")
        assert not facts.yanked
        assert facts.latest == "1.0.0+build.1"
        assert facts.digests == (f"sha256:{self.DIGEST}",)

    @pytest.mark.conformance("helm", "UNI-22")
    def test_unreachable_absent_and_unaskable(self, serve) -> None:
        serve({f"{self.REPO}/index.yaml": RegistryError("connection reset")})
        with pytest.raises(RegistryError):
            MoreRegistries.helm("prometheus-node-exporter", "4.59.0", self.REPO)
        serve({f"{self.REPO}/index.yaml": "apiVersion: v1\nentries: {}\n"})
        with pytest.raises(PackageNotFound):
            MoreRegistries.helm("acme-internal", "1.0.0", self.REPO)
        # A repository named only, or a chart of the project's own: nothing to ask, nothing claimed.
        assert MoreRegistries.helm("redis", "17.3.14", "registry:internal") == PackageFacts(
            name="redis", version="17.3.14"
        )
        with pytest.raises(RegistryError):
            MoreRegistries.helm("../../x", "1", self.REPO)


class TestContainerImages:
    """The OCI distribution API, with `_oci_bytes` (the one transport every image request takes)
    answering from a table."""

    HUB = "https://registry-1.docker.io/v2/library/alpine"
    GHCR = "https://ghcr.io/v2/acme/app"

    @staticmethod
    def sha(data: bytes) -> str:
        import hashlib

        return f"sha256:{hashlib.sha256(data).hexdigest()}"

    @pytest.fixture
    def oci(self, monkeypatch):
        def install(answers: dict[str, Any]) -> Served:
            served = Served(answers)
            monkeypatch.setattr(
                MoreRegistries,
                "_oci_bytes",
                staticmethod(lambda url, accept, follow=False: served(url)),
            )
            return served

        return install

    def platform_index(self) -> tuple[bytes, bytes, bytes]:
        config = json.dumps(
            {
                "config": {
                    "Labels": {"org.opencontainers.image.source": "https://github.com/acme/app"}
                }
            }
        ).encode()
        manifest = json.dumps(
            {"schemaVersion": 2, "config": {"digest": self.sha(config)}, "layers": []}
        ).encode()
        index = json.dumps(
            {
                "schemaVersion": 2,
                "manifests": [
                    {
                        "digest": self.sha(manifest),
                        "platform": {"os": "linux", "architecture": "amd64"},
                    },
                    {
                        "digest": "sha256:" + "c" * 64,
                        "platform": {"os": "unknown", "architecture": "unknown"},
                    },
                ],
            }
        ).encode()
        return index, manifest, config

    @pytest.mark.conformance("image", "UNI-16", "UNI-22", "image.digests")
    def test_a_tag_resolves_to_the_digest_of_the_manifest_as_served(self, oci) -> None:
        index, manifest, config = self.platform_index()
        oci(
            {
                f"{self.GHCR}/tags/list?n=1000": {"tags": ["1.0", "main"]},
                f"{self.GHCR}/manifests/1.0": index,
                f"{self.GHCR}/manifests/{self.sha(manifest)}": manifest,
                f"{self.GHCR}/blobs/{self.sha(config)}": config,
            }
        )
        facts = MoreRegistries.image("ghcr.io/acme/app", "1.0")
        # The index's own digest, then each platform's: a pin may name either.
        assert facts.digests == (self.sha(index), self.sha(manifest), "sha256:" + "c" * 64)
        assert facts.repository == "https://github.com/acme/app" and not facts.yanked
        # No `latest`: tags are not one release line.
        assert facts.latest is None and facts.releases == 2 and facts.attested is False

    @pytest.mark.conformance("image", "UNI-16")
    def test_a_digest_pin_unknown_tags_and_unknown_repositories(self, oci) -> None:
        index, _manifest, _config = self.platform_index()
        digest = self.sha(index)
        oci(
            {
                f"{self.HUB}/tags/list?n=1000": {"tags": ["3.20"]},
                f"{self.HUB}/manifests/{digest}": index,
            }
        )
        assert MoreRegistries.image("alpine", digest).digests[0] == digest
        assert (
            MoreRegistries.image("alpine", "sha256:" + "0" * 64).yanked_reason
            == "not a digest the registry holds"
        )
        assert (
            MoreRegistries.image("alpine", "9.99").yanked_reason == "not a tag the registry holds"
        )
        with pytest.raises(PackageNotFound):
            MoreRegistries.image("acme/nothing", "1.0")

    @pytest.mark.conformance("image", "UNI-22")
    def test_private_registries_and_hostile_references_are_never_asked(self, oci) -> None:
        served = oci({})
        for name, version in (
            ("registry.acme.example.internal/acme/base", "1.0"),
            ("../../etc", "1"),
            ("alpine:3.20", "3.20"),
            ("alpine", "a/../b"),
        ):
            with pytest.raises(RegistryError):
                MoreRegistries.image(name, version)
        assert served.asked == []

    @pytest.mark.conformance("image", "UNI-17")
    def test_attestation_bundles_come_from_the_referrers_of_the_pinned_digest(self, oci) -> None:
        bundle = json.dumps(
            {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "dsseEnvelope": {}}
        ).encode()
        artifact = json.dumps(
            {
                "layers": [
                    {
                        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                        "digest": self.sha(bundle),
                    }
                ]
            }
        ).encode()
        digest = "sha256:" + "d" * 64
        referrers = {
            "manifests": [
                {
                    "artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                    "digest": self.sha(artifact),
                }
            ]
        }
        # No referrers API at this registry: the `sha256-<hex>` tag holds them instead.
        oci(
            {
                f"{self.GHCR}/manifests/{digest.replace(':', '-')}": referrers,
                f"{self.GHCR}/manifests/{self.sha(artifact)}": artifact,
                f"{self.GHCR}/blobs/{self.sha(bundle)}": bundle,
            }
        )
        assert MoreRegistries.image_attestations("ghcr.io/acme/app", digest) == {
            "bundles": [json.loads(bundle)]
        }

    @pytest.mark.conformance("image", "UNI-17", "UNI-22")
    def test_a_blob_whose_bytes_do_not_match_its_digest_is_refused(self, oci) -> None:
        oci({f"{self.GHCR}/blobs/sha256:{'e' * 64}": b"not those bytes"})
        with pytest.raises(RegistryError, match="do not match"):
            MoreRegistries._oci_blob(self.GHCR, "sha256:" + "e" * 64)

    def test_a_blob_redirect_is_followed_over_https_only(self, monkeypatch) -> None:
        import urllib.error
        from email.message import Message

        def redirect(location: str) -> urllib.error.HTTPError:
            headers = Message()
            headers["Location"] = location
            return urllib.error.HTTPError(
                "https://ghcr.io/v2/x/blobs/y", 307, "redirect", headers, None
            )

        monkeypatch.setattr(MoreRegistries, "_get", staticmethod(lambda url, accept="": b"blob"))
        assert (
            MoreRegistries._redirected(redirect("https://pkg-containers.example/blob")) == b"blob"
        )
        with pytest.raises(RegistryError, match="HTTPS"):
            MoreRegistries._redirected(redirect("http://pkg-containers.example/blob"))


class TestHomebrewApi(RegistryFixtures):
    FORMULA: ClassVar[dict[str, Any]] = {
        "name": "jq",
        "homepage": "https://jqlang.github.io/jq/",
        "versions": {"stable": "1.8.2"},
        "revision": 0,
        "urls": {
            "stable": {
                "url": "https://github.com/jqlang/jq/releases/download/jq-1.8.2/jq-1.8.2.tar.gz",
                "checksum": "71b8d6e8f5fe81f6c6d0d110e3892251f6ce76ed095abd315e26e6e1193af3af",
            }
        },
        "bottle": {
            "stable": {
                "files": {
                    "arm64_sonoma": {
                        "sha256": "90b0fe4ad51959380f16fe8d84c5be8ab525478c32f1f7034c72d99de2442c9b"
                    }
                }
            }
        },
        "deprecated": False,
        "disabled": False,
    }

    @pytest.mark.conformance("homebrew", "UNI-16", "UNI-22", "homebrew.urls-checksums")
    def test_the_source_and_bottle_checksums_of_the_current_version(self, serve) -> None:
        serve({"https://formulae.brew.sh/api/formula/jq.json": self.FORMULA})
        facts = MoreRegistries.homebrew("jq", "1.8.2")
        assert facts.digests == (
            "sha256:71b8d6e8f5fe81f6c6d0d110e3892251f6ce76ed095abd315e26e6e1193af3af",
            "sha256:90b0fe4ad51959380f16fe8d84c5be8ab525478c32f1f7034c72d99de2442c9b",
        )
        assert facts.latest == "1.8.2" and not facts.yanked
        # Homebrew keeps one version: an older one has nothing to compare against.
        assert MoreRegistries.homebrew("jq", "1.7.1").digests == ()

    @pytest.mark.conformance("homebrew", "UNI-16")
    def test_disabled_deprecated_and_casks(self, serve) -> None:
        serve(
            {
                "https://formulae.brew.sh/api/formula/old.json": {
                    **self.FORMULA,
                    "name": "old",
                    "disabled": True,
                    "disable_reason": "unmaintained",
                },
                "https://formulae.brew.sh/api/formula/firefox.json": PackageNotFound(
                    "not a formula"
                ),
                "https://formulae.brew.sh/api/cask/firefox.json": {
                    "token": "firefox",
                    "version": "157.0.1",
                    "sha256": "40a0a649120635460256dae9ad63e40377f77326cbc9c449a5d0a1d7f5dd7982",
                    "deprecated": True,
                    "deprecation_reason": "discontinued",
                },
            }
        )
        assert MoreRegistries.homebrew("old", "1.8.2").yanked_reason == "disabled: unmaintained"
        cask = MoreRegistries.homebrew("firefox", "157.0.1")
        assert cask.digests == (
            "sha256:40a0a649120635460256dae9ad63e40377f77326cbc9c449a5d0a1d7f5dd7982",
        )
        assert cask.yanked_reason == "deprecated: discontinued"

    @pytest.mark.conformance("homebrew", "UNI-22")
    def test_unreachable_and_hostile(self, serve) -> None:
        serve({"https://formulae.brew.sh/api/formula/jq.json": RegistryError("connection reset")})
        with pytest.raises(RegistryError):
            MoreRegistries.homebrew("jq", "1.8.2")
        with pytest.raises(RegistryError):
            MoreRegistries.homebrew("../../x", "1")


class TestBazelCentralRegistry(RegistryFixtures):
    BASE = "https://bcr.bazel.build/modules/platforms"
    SOURCE = b'{\n    "url": "https://github.com/bazelbuild/platforms/releases/download/0.0.11/platforms-0.0.11.tar.gz",\n    "integrity": "sha256-KXQuhydYCbXlmNwvBNhpYMx6VbMGfZciHJq7yZJr/w8="\n}\n'
    METADATA: ClassVar[dict[str, Any]] = {
        "repository": ["github:bazelbuild/platforms"],
        "versions": ["0.0.10", "0.0.11", "1.0.0"],
        "yanked_versions": {"0.0.10": "a broken constraint_setting"},
    }

    @pytest.mark.conformance("bazel", "UNI-16", "UNI-22", "bazel.checksums")
    def test_the_source_json_hash_and_the_archive_integrity(self, serve) -> None:
        import hashlib

        serve(
            {
                f"{self.BASE}/metadata.json": self.METADATA,
                f"{self.BASE}/0.0.11/source.json": self.SOURCE,
            }
        )
        facts = MoreRegistries.bazel("platforms", "0.0.11")
        # What a 7.2+ lock records (the file's hash), and what a 7.0 lock records (the archive's).
        assert facts.digests == (
            f"sha256:{hashlib.sha256(self.SOURCE).hexdigest()}",
            "sha256-KXQuhydYCbXlmNwvBNhpYMx6VbMGfZciHJq7yZJr/w8=",
        )
        assert (
            facts.repository == "https://github.com/bazelbuild/platforms"
            and facts.latest == "1.0.0"
        )

    @pytest.mark.conformance("bazel", "UNI-16")
    def test_yanked_and_unknown_versions(self, serve) -> None:
        serve(
            {
                f"{self.BASE}/metadata.json": self.METADATA,
                f"{self.BASE}/0.0.10/source.json": self.SOURCE,
            }
        )
        assert (
            MoreRegistries.bazel("platforms", "0.0.10").yanked_reason
            == "yanked: a broken constraint_setting"
        )
        assert (
            MoreRegistries.bazel("platforms", "9.9.9").yanked_reason
            == "not a version the registry holds"
        )
        with pytest.raises(PackageNotFound):
            MoreRegistries.bazel("acme_internal", "1.0")

    @pytest.mark.conformance("bazel", "UNI-22")
    def test_unreachable_and_hostile(self, serve) -> None:
        serve({f"{self.BASE}/metadata.json": RegistryError("connection reset")})
        with pytest.raises(RegistryError):
            MoreRegistries.bazel("platforms", "0.0.11")
        with pytest.raises(RegistryError):
            MoreRegistries.bazel("../../x", "1")
        with pytest.raises(RegistryError):
            MoreRegistries.bazel("platforms", "1/../../x")


class TestCondaForge(RegistryFixtures):
    URL = "https://api.anaconda.org/package/conda-forge/bzip2/files"

    @pytest.mark.conformance("conda", "UNI-16", "UNI-22")
    def test_every_build_of_the_version_and_its_hashes(self, serve) -> None:
        serve(
            {
                self.URL: [
                    {
                        "version": "1.0.8",
                        "md5": "a" * 32,
                        "sha256": "b" * 64,
                        "labels": ["main"],
                        "basename": "linux-64/bzip2-1.0.8-h4bc722e_7.conda",
                    },
                    {
                        "version": "1.0.8",
                        "md5": "c" * 32,
                        "sha256": "d" * 64,
                        "labels": ["main"],
                        "basename": "osx-arm64/bzip2-1.0.8-h99b78c6_7.conda",
                    },
                    {"version": "1.0.6", "md5": "e" * 32, "sha256": "", "labels": ["main"]},
                ]
            }
        )
        facts = MoreRegistries.conda("bzip2", "1.0.8")
        assert set(facts.digests) == {
            f"sha256:{'b' * 64}",
            f"md5:{'a' * 32}",
            f"sha256:{'d' * 64}",
            f"md5:{'c' * 32}",
        }
        assert facts.releases == 2 and facts.latest == "1.0.8" and not facts.yanked

    @pytest.mark.conformance("conda", "UNI-16")
    def test_a_version_every_build_of_which_is_broken_is_withdrawn(self, serve) -> None:
        serve({self.URL: [{"version": "1.0.8", "md5": "a" * 32, "labels": ["broken"]}]})
        facts = MoreRegistries.conda("bzip2", "1.0.8")
        assert facts.yanked and facts.yanked_reason == "labelled broken by conda-forge"

    @pytest.mark.conformance("conda", "UNI-22")
    def test_a_package_conda_forge_lacks_is_not_checked_rather_than_missing(self, serve) -> None:
        serve({})
        with pytest.raises(RegistryError) as raised:
            MoreRegistries.conda("bzip2", "1.0.8")
        assert not isinstance(raised.value, PackageNotFound)


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

    @pytest.mark.parametrize("ecosystem", ["pub", "cocoapods", "cargo", "npm"])
    def test_the_projects_own_code_is_never_asked(self, monkeypatch, ecosystem) -> None:
        # A path dependency asked of the public registry leaked its name and came back "not on
        # the public pub registry" (appmetrica) or "withdrawn" (FlutterMacOS).
        from dataclasses import replace

        asked: list[str] = []
        monkeypatch.setattr(
            "cordon_scanner.intel.registry_client.RegistryClient.facts",
            lambda ecosystem, name, version: (
                asked.append(name) or PackageFacts(name=name, version=version, yanked=True)
            ),
        )
        local = replace(self.dependency(ecosystem, "appmetrica"), local=True)
        assert self.ids(local) == [] and asked == []

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

    def test_a_pubspec_lock_with_a_malformed_hash_records_it_as_malformed(self) -> None:
        """A `sha256` that is not one is the tampering case: recorded as malformed (and reported),
        never dropped as if the entry had no hash -- and never echoed."""
        text = 'packages:\n  http:\n    description:\n      name: http\n      sha256: nothex\n    version: "1.0.0"\n'
        (entry,) = self.entries("pubspec.lock", text)
        assert entry.integrity is not None and entry.integrity.startswith("malformed:")
        assert "nothex" not in entry.integrity
