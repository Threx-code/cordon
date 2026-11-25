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


class TestEveryRecordIsSerialisable:
    @pytest.mark.parametrize(
        ("ecosystem", "name", "version", "files"),
        [
            ("cargo", "fnv", "1.0.7", TestCargo.FILES),
            ("rubygems", "abbrev", "0.1.2", TestRubygems.FILES),
            ("hex", "plug_crypto", "1.1.2", TestHex.FILES),
            ("pub", "equatable", "0.1.2", TestPub.FILES),
        ],
    )
    def test_a_record_survives_the_store(self, tmp_path, ecosystem, name, version, files) -> None:
        record = Fixtures.record(ecosystem, name, version, files)
        assert record is not None
        record.save(tmp_path)
        assert RegistryRecord.load(ecosystem, name, version, tmp_path) == record
        assert record.facts()["reg_known"] == 1.0
