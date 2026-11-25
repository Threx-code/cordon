"""The shared interface of the registry record (`intel/registries/record_sources`): one source per ecosystem, one builder, one fetch."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, ClassVar

import pytest

from cordon_scanner.intel.registries import registry_client
from cordon_scanner.intel.registries.record_sources.base import (
    Document,
    PublisherKind,
    RecordBuilder,
    RecordFetch,
    RecordSource,
    Release,
)
from cordon_scanner.intel.registries.record_sources.table import RecordSources
from cordon_scanner.intel.registries.registry_record import ECOSYSTEMS, RegistryRecord
from cordon_scanner.intel.registries.registry_request import PackageNotFound

T0 = datetime(2026, 1, 1, 12, 0, 0)


class Toy(RecordSource):
    """A source made only to exercise the interface: two JSON documents and one text one."""

    ecosystem: ClassVar[str] = "toy"
    publisher_kind: ClassVar[PublisherKind] = "committer"

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        return (
            Document(f"https://registry.example.invalid/{name}.json"),
            Document(
                f"https://registry.example.invalid/{name}/notes.txt", kind="text", required=False
            ),
            Document(
                f"https://api.example.invalid/{name}/commits", needs_token=True, required=False
            ),
        )

    def record(self, name: str, version: str, documents: Any) -> RegistryRecord | None:
        return None


class TestTheBuilder:
    RELEASES: ClassVar[list[Release]] = [
        Release("1.0.0", T0, "alice"),
        Release("1.1.0", T0 + timedelta(hours=2), "alice"),
        Release("1.2.0", T0 + timedelta(hours=20), "mallory", withdrawn="yanked"),
        Release("2.0.0", T0 + timedelta(days=30), "alice"),
    ]

    def build(self, version: str, **facts: Any) -> RegistryRecord | None:
        return RecordBuilder.from_history(
            Toy(), "pkg", version, list(reversed(self.RELEASES)), **facts
        )

    def test_the_counts_are_of_what_came_before_the_release(self) -> None:
        record = self.build("1.2.0")
        assert record is not None
        assert (record.prior_versions, record.prior_24h, record.previous_version) == (2, 2, "1.1.0")
        assert record.prior_publishers == ("alice",) and record.publisher == "mallory"

    def test_the_release_is_found_whatever_the_order_of_the_history(self) -> None:
        assert self.build("1.0.0") is not None and self.build("1.0.0").prior_versions == 0  # type: ignore[union-attr]

    def test_the_registrys_word_for_a_withdrawal_and_the_kind_of_publisher_are_kept(self) -> None:
        record = self.build("1.2.0")
        assert record is not None and (record.withdrawn, record.publisher_kind) == (
            "yanked",
            "committer",
        )
        assert self.build("1.0.0").withdrawn == ""  # type: ignore[union-attr]

    def test_a_burst_is_counted_in_the_day_before_the_release(self) -> None:
        record = self.build("2.0.0")
        assert record is not None and record.prior_24h == 0 and record.prior_versions == 3

    def test_the_name_is_as_old_as_the_registry_says_when_it_says(self) -> None:
        record = self.build("1.2.0", created=T0 - timedelta(days=400))
        assert record is not None and record.created.startswith("2024-")

    def test_a_release_the_history_does_not_hold_has_no_record(self) -> None:
        assert self.build("9.9.9") is None

    def test_the_other_facts_ride_into_the_record(self) -> None:
        record = self.build("1.0.0", maintainers=3, has_repository=True)
        assert record is not None and record.maintainers == 3 and record.has_repository


class TestTheFetch:
    def patch(self, monkeypatch, *, json_for=None, text_for=None) -> list[str]:
        asked: list[str] = []

        def fetch_json(url: str) -> Any:
            asked.append(url)
            if json_for is None or url not in json_for:
                raise PackageNotFound("no such name")
            return json_for[url]

        def fetch_text(url: str) -> str:
            asked.append(url)
            if text_for is None or url not in text_for:
                raise PackageNotFound("no such file")
            return text_for[url]

        from cordon_scanner.intel.registries.registry_http import RegistryHttp

        monkeypatch.setattr(registry_client.RegistryClient, "_fetch", staticmethod(fetch_json))
        monkeypatch.setattr(RegistryHttp, "text", staticmethod(fetch_text))
        return asked

    def test_every_document_is_fetched_by_its_kind_and_keyed_by_its_url(self, monkeypatch) -> None:
        asked = self.patch(
            monkeypatch,
            json_for={"https://registry.example.invalid/pkg.json": {"a": 1}},
            text_for={"https://registry.example.invalid/pkg/notes.txt": "hello"},
        )
        got = RecordFetch.documents(Toy(), "pkg", "1.0.0")
        assert got == {
            "https://registry.example.invalid/pkg.json": {"a": 1},
            "https://registry.example.invalid/pkg/notes.txt": "hello",
            "https://api.example.invalid/pkg/commits": None,
        }
        assert "https://api.example.invalid/pkg/commits" not in asked  # no token: never asked

    def test_a_document_that_needs_a_token_is_asked_only_with_one(self, monkeypatch) -> None:
        asked = self.patch(
            monkeypatch,
            json_for={
                "https://registry.example.invalid/pkg.json": {},
                "https://api.example.invalid/pkg/commits": [1],
            },
        )
        got = RecordFetch.documents(Toy(), "pkg", "1.0.0", token="t")
        assert got is not None and got["https://api.example.invalid/pkg/commits"] == [1]
        assert "https://api.example.invalid/pkg/commits" in asked

    def test_a_missing_required_document_means_the_registry_does_not_hold_the_name(
        self, monkeypatch
    ) -> None:
        self.patch(monkeypatch)
        assert RecordFetch.documents(Toy(), "pkg", "1.0.0") is None

    def test_a_missing_optional_document_is_passed_as_none(self, monkeypatch) -> None:
        self.patch(monkeypatch, json_for={"https://registry.example.invalid/pkg.json": {}})
        got = RecordFetch.documents(Toy(), "pkg", "1.0.0")
        assert got is not None and got["https://registry.example.invalid/pkg/notes.txt"] is None

    def test_a_source_that_wants_too_many_documents_is_refused(self, monkeypatch) -> None:
        class Greedy(Toy):
            def documents(self, name: str, version: str) -> tuple[Document, ...]:
                return tuple(
                    Document(f"https://r.example.invalid/{n}")
                    for n in range(RecordFetch.MAX_DOCUMENTS + 1)
                )

        self.patch(monkeypatch)
        with pytest.raises(ValueError, match="at most"):
            RecordFetch.documents(Greedy(), "pkg", "1.0.0")


class TestTheTable:
    def test_the_table_and_the_constant_name_the_same_ecosystems(self) -> None:
        assert RecordSources.ecosystems() == ECOSYSTEMS

    def test_every_source_asks_https_documents_and_says_what_its_publisher_is(self) -> None:
        for source in RecordSources.SOURCES:
            documents = source.documents("example", "1.0.0")
            assert documents and all(d.url.startswith("https://") for d in documents), (
                source.ecosystem
            )
            assert source.publisher_kind in ("account", "namespace", "committer", "none")

    def test_an_ecosystem_with_no_source_has_none(self) -> None:
        assert RecordSources.of("not-an-ecosystem") is None

    def test_the_two_sources_that_exist_read_what_they_always_did(self, monkeypatch) -> None:
        packument = {
            "name": "left-pad",
            "time": {
                "created": "2016-03-01T00:00:00Z",
                "1.0.0": "2016-03-01T00:00:00Z",
                "1.1.0": "2016-04-01T00:00:00Z",
            },
            "versions": {
                "1.0.0": {"_npmUser": {"name": "azer"}},
                "1.1.0": {"_npmUser": {"name": "azer"}},
            },
        }
        source = RecordSources.of("npm")
        assert source is not None
        record = source.record(
            "left-pad", "1.1.0", {"https://registry.npmjs.org/left-pad": packument}
        )
        assert record is not None and (record.prior_versions, record.publisher) == (1, "azer")
        assert record.publisher_kind == "account"
        pypi = RecordSources.of("pypi")
        assert pypi is not None and pypi.publisher_kind == "namespace"
