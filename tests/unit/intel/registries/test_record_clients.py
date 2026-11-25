"""The registry record of each ecosystem read from the registry's real documents (`record_sources/`).

Every fixture in `records/` is a real answer captured from the registry on 2026-11-25 (public metadata only; an owner's e-mail
address is removed). What is tested is what the record says: when, who, what came before, whether it was withdrawn."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from cordon_scanner.intel.registries.record_sources.table import RecordSources
from cordon_scanner.intel.registries.registry_record import RegistryRecord
from support import ROOT

DATA = ROOT / "tests" / "unit" / "intel" / "registries" / "records"


class Fixtures:
    @staticmethod
    def load(name: str) -> Any:
        return json.loads((DATA / name).read_text(encoding="utf-8"))

    @classmethod
    def record(
        cls,
        ecosystem: str,
        name: str,
        version: str,
        files: tuple[str | None, ...],
        edit: Any = None,
    ) -> RegistryRecord | None:
        """The record of `version`, with the source's documents bound to `files` in order (None: a document the registry did not serve)."""
        source = RecordSources.of(ecosystem)
        assert source is not None
        wanted = source.documents(name, version)
        assert len(wanted) == len(files), "one fixture (or None) for each document the source asks"
        documents: dict[str, Any] = {}
        for document, file in zip(wanted, files, strict=True):
            documents[document.url] = copy.deepcopy(cls.load(file)) if file else None
        if edit is not None:
            edit(documents)
        return source.record(name, version, documents)


class TestCargo:
    FILES = ("cargo.json", "cargo_owners.json")

    def record(self, version: str, edit: Any = None) -> RegistryRecord:
        found = Fixtures.record("cargo", "fnv", version, self.FILES, edit)
        assert found is not None
        return found

    def test_the_newest_release_with_its_publisher_and_its_history(self) -> None:
        record = self.record("1.0.7")
        assert (record.published, record.created) == ("2020-05-14T16:06:29", "2015-04-06T18:59:35")
        assert (record.prior_versions, record.previous_version, record.publisher) == (
            7,
            "1.0.6",
            "Manishearth",
        )
        assert record.publisher_kind == "account" and record.withdrawn == ""

    def test_the_owners_are_the_crates_and_a_publish_bot_is_one(self) -> None:
        record = self.record("1.0.7")
        assert (
            record.owners == ("SimonSapin", "github:servo:cargo-publish")
            and record.maintainers == 2
        )

    def test_an_old_release_the_registry_names_no_publisher_for(self) -> None:
        record = self.record("1.0.3")
        assert record.publisher == "" and record.prior_publishers == ()

    def test_a_yanked_release_says_so_in_the_registrys_word(self) -> None:
        def yank(documents: dict[str, Any]) -> None:
            next(iter(documents.values()))["versions"][0]["yanked"] = True

        assert self.record("1.0.7", yank).withdrawn == "yanked"

    def test_without_the_owners_document_the_record_is_still_made(self) -> None:
        found = Fixtures.record("cargo", "fnv", "1.0.7", ("cargo.json", None))
        assert found is not None and found.maintainers == 0

    def test_a_version_the_crate_does_not_have(self) -> None:
        assert Fixtures.record("cargo", "fnv", "9.9.9", self.FILES) is None


class TestRubygems:
    FILES = ("rubygems_versions.json", "rubygems_gem.json", "rubygems_owners.json")

    def test_the_newest_release_knows_its_manifest(self) -> None:
        record = Fixtures.record("rubygems", "abbrev", "0.1.2", self.FILES)
        assert record is not None
        assert (record.published, record.prior_versions, record.previous_version) == (
            "2023-12-16T05:04:20",
            2,
            "0.1.1",
        )
        assert record.manifest_known and record.has_author and record.publisher_kind == "namespace"

    def test_the_owners_of_the_gem_are_named_and_not_a_publisher(self) -> None:
        record = Fixtures.record("rubygems", "abbrev", "0.1.2", self.FILES)
        assert record is not None and record.owners == ("hsbt", "naruse") and record.publisher == ""

    def test_an_older_release_does_not_borrow_the_newest_ones_manifest(self) -> None:
        record = Fixtures.record("rubygems", "abbrev", "0.1.1", self.FILES)
        assert record is not None and not record.manifest_known and not record.has_author

    def test_a_platform_gem_counts_once_at_its_earliest_push(self) -> None:
        def duplicate(documents: dict[str, Any]) -> None:
            versions = next(iter(documents.values()))
            later = copy.deepcopy(versions[0])
            later["created_at"] = "2024-06-01T00:00:00.000Z"
            later["platform"] = "java"
            versions.append(later)

        found = Fixtures.record("rubygems", "abbrev", "0.1.2", self.FILES, duplicate)
        assert (
            found is not None
            and found.prior_versions == 2
            and found.published.startswith("2023-12-16")
        )

    def test_a_gem_the_registry_does_not_list_this_version_of(self) -> None:
        assert Fixtures.record("rubygems", "abbrev", "9.9.9", self.FILES) is None


class TestHex:
    FILES = ("hex.json",)

    def test_the_release_its_history_and_the_name_age(self) -> None:
        record = Fixtures.record("hex", "plug_crypto", "1.1.2", self.FILES)
        assert record is not None
        assert record.created.startswith("2018-10-03") and record.published.startswith("2020-02-15")
        assert (record.prior_versions, record.previous_version) == (3, "1.1.1")

    def test_the_owners_and_what_kind_of_publisher_that_is(self) -> None:
        record = Fixtures.record("hex", "plug_crypto", "1.1.2", self.FILES)
        assert record is not None and record.owners == ("ericmj", "josevalim", "whatyouhide")
        assert record.publisher_kind == "namespace" and "@" not in "".join(record.owners)

    def test_a_retired_release_says_so_in_the_registrys_word(self) -> None:
        record = Fixtures.record("hex", "plug_crypto", "1.1.1", self.FILES)
        assert record is not None and record.withdrawn == "retired"
        other = Fixtures.record("hex", "plug_crypto", "1.1.2", self.FILES)
        assert other is not None and other.withdrawn == ""

    def test_a_release_the_day_after_the_one_before_it_is_not_a_burst_and_one_an_hour_after_is(
        self,
    ) -> None:
        quiet = Fixtures.record("hex", "plug_crypto", "1.1.1", self.FILES)
        assert quiet is not None and quiet.prior_24h == 0

        def hurry(documents: dict[str, Any]) -> None:
            releases = next(iter(documents.values()))["releases"]
            when = next(r["inserted_at"] for r in releases if r["version"] == "1.1.1")
            next(r for r in releases if r["version"] == "1.1.0")["inserted_at"] = when.replace(
                "10:27:59", "09:27:59"
            )

        burst = Fixtures.record("hex", "plug_crypto", "1.1.1", self.FILES, hurry)
        assert burst is not None and burst.prior_24h == 1


class TestPub:
    FILES = ("pub.json", None)

    def test_the_first_release_has_no_history(self) -> None:
        record = Fixtures.record("pub", "equatable", "0.1.0", self.FILES)
        assert record is not None and (record.prior_versions, record.previous_version) == (0, "")
        assert record.published.startswith("2019-01-06")

    def test_a_later_release_names_the_one_before_it(self) -> None:
        record = Fixtures.record("pub", "equatable", "0.1.2", self.FILES)
        assert (
            record is not None and record.previous_version == "0.1.1" and record.prior_versions == 2
        )

    def test_a_retracted_release_says_so_in_the_registrys_word(self) -> None:
        def retract(documents: dict[str, Any]) -> None:
            next(iter(documents.values()))["versions"][1]["retracted"] = True

        record = Fixtures.record("pub", "equatable", "0.1.1", self.FILES, retract)
        assert record is not None and record.withdrawn == "retracted"

    def test_the_verified_publisher_is_the_one_the_registry_names(self) -> None:
        def verified(documents: dict[str, Any]) -> None:
            urls = list(documents)
            documents[urls[1]] = {"publisherId": "dash.example"}

        record = Fixtures.record("pub", "equatable", "0.1.2", self.FILES, verified)
        assert (
            record is not None
            and record.publisher == "dash.example"
            and record.prior_publishers == ("dash.example",)
        )

    def test_without_a_verified_publisher_the_registry_names_none(self) -> None:
        record = Fixtures.record("pub", "equatable", "0.1.2", self.FILES)
        assert record is not None and record.publisher == ""


class TestComposer:
    FILES = ("composer.json",)
    NAME = "psr/log"

    def test_the_minified_list_is_made_whole_before_it_is_read(self) -> None:
        expanded = RecordSources.of("composer").expand(
            Fixtures.load("composer.json")["packages"][self.NAME]
        )  # type: ignore[union-attr]
        assert len(expanded) == 12 and all(
            e["version"] and e["time"] and e["name"] == self.NAME for e in expanded
        )

    def test_the_newest_release_its_history_and_what_a_publisher_is_here(self) -> None:
        record = Fixtures.record("composer", self.NAME, "3.0.2", self.FILES)
        assert record is not None
        assert (record.published, record.prior_versions, record.previous_version) == (
            "2024-09-11T13:17:53",
            11,
            "3.0.1",
        )
        assert (
            record.created.startswith("2012-12-21")
            and record.publisher_kind == "none"
            and record.publisher == ""
        )

    def test_an_abandoned_package_is_withdrawn_in_the_registrys_word_and_the_flag_is_inherited_down_the_list(
        self,
    ) -> None:
        def abandon(documents: dict[str, Any]) -> None:
            next(iter(documents.values()))["packages"][self.NAME][0]["abandoned"] = True

        newest = Fixtures.record("composer", self.NAME, "3.0.2", self.FILES, abandon)
        oldest = Fixtures.record("composer", self.NAME, "1.0.0", self.FILES, abandon)
        assert newest is not None and newest.withdrawn == "abandoned"
        assert oldest is not None and oldest.withdrawn == "abandoned"

    def test_a_key_a_later_entry_unsets_is_gone_from_it(self) -> None:
        def abandon_then_forgive(documents: dict[str, Any]) -> None:
            entries = next(iter(documents.values()))["packages"][self.NAME]
            entries[0]["abandoned"] = True
            entries[1]["abandoned"] = "__unset"

        forgiven = Fixtures.record("composer", self.NAME, "3.0.1", self.FILES, abandon_then_forgive)
        assert forgiven is not None and forgiven.withdrawn == ""

    @pytest.mark.parametrize(
        "name", ["Psr/Log", "psr", "psr/log/extra", "../../x/y", "psr/log?x", ""]
    )
    def test_a_name_that_is_not_vendor_slash_package_asks_for_nothing(self, name: str) -> None:
        assert RecordSources.of("composer").documents(name, "1.0.0") == ()  # type: ignore[union-attr]


class TestCocoapods:
    FILES = ("cocoapods.json",)

    def test_the_newest_release_and_the_trunk_time_format(self) -> None:
        record = Fixtures.record("cocoapods", "Alamofire", "5.9.1", self.FILES)
        assert record is not None
        assert record.published == "2024-03-31T01:24:57" and record.prior_versions == 91
        assert record.publisher_kind == "namespace" and record.created.startswith("2015-01-09")

    def test_the_owners_are_named_and_no_address_is_kept(self) -> None:
        record = Fixtures.record("cocoapods", "Alamofire", "5.9.1", self.FILES)
        assert (
            record is not None
            and "Christian Noon" in record.owners
            and record.maintainers == len(record.owners)
        )
        assert not any("@" in owner for owner in record.owners)

    def test_a_version_the_pod_does_not_have(self) -> None:
        assert Fixtures.record("cocoapods", "Alamofire", "99.0.0", self.FILES) is None

    @pytest.mark.parametrize("name", ["", "../x", "a/b", "a b", ".hidden"])
    def test_a_name_that_is_not_a_pod_name_asks_for_nothing(self, name: str) -> None:
        assert RecordSources.of("cocoapods").documents(name, "1.0.0") == ()  # type: ignore[union-attr]


class TestAnsible:
    NAME = "community.general"
    FILES = ("ansible.json", None)

    def test_the_newest_release_on_the_first_page(self) -> None:
        record = Fixtures.record("ansible", self.NAME, "14.0.1", self.FILES)
        assert record is not None
        assert (record.published, record.prior_versions, record.previous_version) == (
            "2026-11-09T19:50:45",
            19,
            "14.0.0",
        )
        assert record.publisher == "community" and record.publisher_kind == "namespace"

    def test_a_deprecated_collection_says_so(self) -> None:
        def deprecate(documents: dict[str, Any]) -> None:
            documents[list(documents)[1]] = {"deprecated": True}

        record = Fixtures.record(
            "ansible", self.NAME, "14.0.1", (*self.FILES[:1], "ansible.json"), deprecate
        )
        assert record is not None and record.withdrawn == "deprecated"

    def test_the_next_page_is_asked_for_and_only_on_this_registrys_own_path(self) -> None:
        source = RecordSources.of("ansible")
        assert source is not None
        first = next(iter(source.documents(self.NAME, "14.0.1"))).url
        found = {first: Fixtures.load("ansible.json")}
        asked = [d.url for d in source.followed(self.NAME, "14.0.1", found)]
        assert asked == ["https://galaxy.ansible.com" + found[first]["links"]["next"]]

        found[first]["links"]["next"] = "https://evil.example.invalid/api/v3/x/versions/?offset=20"
        assert source.followed(self.NAME, "14.0.1", found) == ()

    def test_the_fetch_follows_the_pages_until_there_are_no_more_and_never_loops(
        self, monkeypatch
    ) -> None:
        from cordon_scanner.intel.registries import registry_client
        from cordon_scanner.intel.registries.record_sources.base import RecordFetch

        first = Fixtures.load("ansible.json")
        second = {
            "data": [{"version": "0.0.1", "created_at": "2020-01-01T00:00:00Z"}],
            "links": {"next": first["links"]["next"]},
        }
        calls: list[str] = []

        def fetch(url: str) -> Any:
            calls.append(url)
            return second if "offset=20" in url else first

        monkeypatch.setattr(registry_client.RegistryClient, "_fetch", staticmethod(fetch))
        source = RecordSources.of("ansible")
        assert source is not None
        documents = RecordFetch.documents(source, self.NAME, "14.0.1")
        assert (
            documents is not None and len(calls) == len(set(calls)) == 3
        )  # first, collection, page 2; page 2 points to itself
        record = source.record(self.NAME, "14.0.1", documents)
        assert (
            record is not None
            and record.prior_versions == 20
            and record.created.startswith("2020-01-01")
        )

    @pytest.mark.parametrize("name", ["general", "a.b.c", "Community.General", "../x.y", ""])
    def test_a_name_that_is_not_namespace_dot_name_asks_for_nothing(self, name: str) -> None:
        assert RecordSources.of("ansible").documents(name, "1.0.0") == ()  # type: ignore[union-attr]


class TestConda:
    FILES = ("conda.json",)

    def test_a_version_is_as_old_as_its_earliest_file(self) -> None:
        record = Fixtures.record("conda", "zlib", "1.3.2", self.FILES)
        assert record is not None
        assert (record.published, record.prior_versions, record.previous_version) == (
            "2026-03-21T" + record.published[11:],
            6,
            "1.3.1",
        )
        assert (
            record.publisher == "conda-forge"
            and record.publisher_kind == "namespace"
            and record.manifest_known
        )

    def test_an_older_release_does_not_borrow_the_newest_ones_manifest(self) -> None:
        record = Fixtures.record("conda", "zlib", "1.3.1", self.FILES)
        assert record is not None and not record.manifest_known

    def test_the_channel_may_be_named(self) -> None:
        source = RecordSources.of("conda")
        assert source is not None
        assert (
            source.documents("zlib", "1.3.2")[0].url
            == source.documents("conda-forge/zlib", "1.3.2")[0].url
        )
        assert source.documents("anaconda/zlib", "1.3.2")[0].url.endswith("/package/anaconda/zlib")

    @pytest.mark.parametrize("name", ["", "../zlib", "a/b/c", "Zlib", "z lib", "a/../b"])
    def test_a_name_that_is_not_a_package_asks_for_nothing(self, name: str) -> None:
        assert RecordSources.of("conda").documents(name, "1") == ()  # type: ignore[union-attr]


class TestNuget:
    FILES = ("nuget_index.json",)
    NAME = "Newtonsoft.Json"

    def test_the_first_release_and_the_next(self) -> None:
        first = Fixtures.record("nuget", self.NAME, "3.5.8", self.FILES)
        second = Fixtures.record("nuget", self.NAME, "4.0.1", self.FILES)
        assert (
            first is not None
            and first.prior_versions == 0
            and first.published.startswith("2011-01-08")
        )
        assert second is not None and (second.prior_versions, second.previous_version) == (
            1,
            "3.5.8",
        )
        assert second.publisher_kind == "none" and second.has_author

    def test_the_history_runs_across_the_pages_of_the_index(self) -> None:
        record = Fixtures.record("nuget", self.NAME, "12.0.1", self.FILES)
        assert record is not None and record.prior_versions == 46

    def test_an_unlisted_release_says_so_in_the_registrys_word(self) -> None:
        def unlist(documents: dict[str, Any]) -> None:
            index = next(iter(documents.values()))
            index["items"][0]["items"][1]["catalogEntry"]["listed"] = False

        record = Fixtures.record("nuget", self.NAME, "4.0.1", self.FILES, unlist)
        assert record is not None and record.withdrawn == "unlisted"

    def test_the_sentinel_date_of_an_unlisted_package_is_not_a_date(self) -> None:
        def sentinel(documents: dict[str, Any]) -> None:
            index = next(iter(documents.values()))
            index["items"][0]["items"][2]["catalogEntry"]["published"] = "1900-01-01T00:00:00+00:00"

        before = Fixtures.record("nuget", self.NAME, "4.0.1", self.FILES, sentinel)
        assert before is not None and before.prior_versions == 1
        assert Fixtures.record("nuget", self.NAME, "4.0.2", self.FILES, sentinel) is None

    def test_a_page_that_is_not_inline_is_a_document_of_this_package_only(self) -> None:
        source = RecordSources.of("nuget")
        assert source is not None
        base = "https://api.nuget.org/v3/registration5-gz-semver2/newtonsoft.json/"
        index = {
            "items": [
                {"@id": base + "page/1.0.0/2.0.0.json", "count": 3},
                {"@id": "https://evil.example.invalid/p.json", "count": 1},
            ]
        }
        asked = source.followed(self.NAME, "1.0.0", {base + "index.json": index})
        assert [d.url for d in asked] == [base + "page/1.0.0/2.0.0.json"]

    @pytest.mark.parametrize("name", ["", "../x", "a/b", "a b", ".x", "x" * 101])
    def test_a_name_that_is_not_a_package_id_asks_for_nothing(self, name: str) -> None:
        assert RecordSources.of("nuget").documents(name, "1.0.0") == ()  # type: ignore[union-attr]


class TestEveryRecordIsSerialisable:
    @pytest.mark.parametrize(
        ("ecosystem", "name", "version", "files"),
        [
            ("cargo", "fnv", "1.0.7", TestCargo.FILES),
            ("rubygems", "abbrev", "0.1.2", TestRubygems.FILES),
            ("hex", "plug_crypto", "1.1.2", TestHex.FILES),
            ("pub", "equatable", "0.1.2", TestPub.FILES),
            ("composer", "psr/log", "3.0.2", TestComposer.FILES),
            ("cocoapods", "Alamofire", "5.9.1", TestCocoapods.FILES),
            ("conda", "zlib", "1.3.2", TestConda.FILES),
            ("nuget", "Newtonsoft.Json", "4.0.1", TestNuget.FILES),
        ],
    )
    def test_a_record_survives_the_store(self, tmp_path, ecosystem, name, version, files) -> None:
        record = Fixtures.record(ecosystem, name, version, files)
        assert record is not None
        record.save(tmp_path)
        assert RegistryRecord.load(ecosystem, name, version, tmp_path) == record
        assert record.facts()["reg_known"] == 1.0
