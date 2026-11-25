"""The registry record of the git-hosted registries and of packages that are repositories, read from the real answers
of each host (captured once, trimmed to the fields read: `git_hosted_records.json`)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest

from cordon_scanner.intel.registries.record_sources import git_hosted
from cordon_scanner.intel.registries.record_sources.git_hosted import GitHub, History
from cordon_scanner.intel.registries.record_sources.table import RecordSources
from cordon_scanner.intel.registries.registry_record import ECOSYSTEMS
from support import ROOT

DOCUMENTS: dict[str, Any] = json.loads(
    (ROOT / "tests/unit/intel/registries/git_hosted_records.json").read_text(encoding="utf-8")
)
NIX_REV = "b134951a4c9f3c995fd7be05f3243f8ecd65d798"

#: ecosystem: (name, version, published, previous version, publisher), each checked against the host's own answer.
EXPECTED: dict[str, tuple[str, str, str, str, str]] = {
    "bazel": ("rules_cc", "0.2.27", "2026-10-22T22:51:18+00:00", "0.2.26", "armandomontanez"),
    "julia": ("JSON", "0.21.4", "2023-04-12T15:09:16+00:00", "0.21.3", "JuliaRegistrator"),
    "vcpkg": ("zlib", "1.3.1", "2024-01-30T20:58:10+00:00", "1.3", ""),
    "opam": ("yojson", "2.2.2", "2024-06-27T14:51:25+00:00", "2.2.1", "Leonidas-from-XIV"),
    "conan": ("zlib", "1.3.1", "2024-01-23T08:39:53+00:00", "1.3", ""),
    "homebrew": ("jq", "1.8.2", "2026-06-20T14:53:25+00:00", "1.8.1", "BrewTestBot"),
    "actions": ("actions/checkout", "v4.2.2", "2024-10-23T14:46:00+00:00", "v4.2.1", "jww3"),
    "swift": ("alamofire/alamofire", "5.8.1", "2023-10-26T19:49:10+00:00", "5.8.0", "jshier"),
    "nix": (
        "nixos/nixpkgs",
        NIX_REV,
        "2024-12-30T13:00:28+00:00",
        "1d8eab1b0dadd466a5d9a6568a43b78ff74d3a38",
        "vcunat",
    ),
}


class Kit:
    @staticmethod
    def record(ecosystem: str, name: str, version: str, drop: str = "") -> Any:
        source = RecordSources.of(ecosystem)
        assert source is not None
        wanted = {
            d.url: (None if drop and drop in d.url else DOCUMENTS.get(d.url))
            for d in source.documents(name, version)
        }
        return source.record(name, version, wanted)


class TestEveryGitHostedEcosystem:
    def test_each_is_in_the_table_and_the_record_ecosystems(self) -> None:
        ids = {s.ecosystem for s in git_hosted.SOURCES}
        assert ids == set(EXPECTED)
        assert ids <= RecordSources.ecosystems() and ids <= ECOSYSTEMS

    @pytest.mark.parametrize("ecosystem", sorted(EXPECTED))
    def test_every_document_it_reads_is_a_captured_real_answer(self, ecosystem: str) -> None:
        name, version, *_ = EXPECTED[ecosystem]
        source = RecordSources.of(ecosystem)
        assert source is not None
        assert all(d.url in DOCUMENTS for d in source.documents(name, version))

    @pytest.mark.parametrize("ecosystem", sorted(EXPECTED))
    def test_the_record_is_what_the_host_says(self, ecosystem: str) -> None:
        name, version, published, previous, publisher = EXPECTED[ecosystem]
        record = Kit.record(ecosystem, name, version)
        assert record is not None
        assert (record.ecosystem, record.name, record.version) == (ecosystem, name, version)
        assert (record.published, record.previous_version, record.publisher) == (
            published,
            previous,
            publisher,
        )
        assert record.prior_versions >= 1 and record.publisher_kind

    @pytest.mark.parametrize("ecosystem", sorted(EXPECTED))
    def test_a_version_the_host_does_not_hold_has_no_record(self, ecosystem: str) -> None:
        name, *_ = EXPECTED[ecosystem]
        assert Kit.record(ecosystem, name, "999.999.999-not-a-release") is None

    @pytest.mark.parametrize("ecosystem", sorted(set(EXPECTED) - {"nix", "actions", "swift"}))
    def test_without_its_release_list_there_is_no_record(self, ecosystem: str) -> None:
        name, version, *_ = EXPECTED[ecosystem]
        source = RecordSources.of(ecosystem)
        assert source is not None
        listing = source.documents(name, version)[0].url
        assert Kit.record(ecosystem, name, version, drop=listing) is None


class TestDating:
    T = datetime(2026, 1, 1, tzinfo=UTC)

    @staticmethod
    def commit(message: str, day: int, who: str = "a") -> dict[str, Any]:
        stamp = f"2026-01-{day:02d}T00:00:00Z"
        return {
            "sha": "0" * 40,
            "commit": {"message": message, "author": {"date": stamp}},
            "author": {"login": who},
        }

    def test_the_earliest_commit_naming_a_release_dates_it(self) -> None:
        commits = [self.commit("demo 1.2 bottle", 9), self.commit("demo 1.2", 5, "b")]
        assert History.dated(["1.2"], commits)["1.2"] == (datetime(2026, 1, 5, tzinfo=UTC), "b")

    def test_a_longer_version_or_another_package_does_not_date_it(self) -> None:
        commits = [self.commit("demo 1.2.3", 3), self.commit("other 1.2", 4)]
        assert History.dated(["1.2"], commits, ("demo",)) == {}

    def test_an_undated_release_keeps_its_place_between_the_dated_ones(self) -> None:
        dated = {"1.0": (self.T, "a"), "2.0": (self.T.replace(day=9), "b")}
        releases = History.releases(["1.0", "1.0#1", "2.0"], dated)
        assert [r.version for r in sorted(releases, key=lambda r: r.published)] == [
            "1.0",
            "1.0#1",
            "2.0",
        ]
        assert releases[1].published < releases[2].published

    def test_a_hostile_answer_gives_no_record_and_no_error(self) -> None:
        assert GitHub.commits({"x": "not a list", "y": [1, None, {"commit": 3}]}, "") == [
            {"commit": 3}
        ]
        assert GitHub.commit_fact({"commit": 3}) == ("", None, "")
