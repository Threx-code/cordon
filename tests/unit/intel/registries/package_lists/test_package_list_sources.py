"""Each registry's source reads that registry's real response.

The pages in `pages_captures/` are real responses from each registry's public API (see `pages_captures/CAPTURES.md`), trimmed to whole
entries. The fetchers are run against them with the network replaced, so a registry that changes its response
shape fails here instead of writing a short list.
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import math
import tomllib
from typing import Any

import pytest
from refresh_script import RefreshScript

from support import ROOT


class Pages:
    DIRECTORY = (
        ROOT / "tests" / "unit" / "intel" / "registries" / "package_lists" / "pages_captures"
    )

    @classmethod
    def read(cls, name: str) -> Any:
        return json.loads((cls.DIRECTORY / name).read_text(encoding="utf-8"))


class Offline:
    """The refresh script with its waits removed, run from the repository."""

    @pytest.fixture(autouse=True)
    def _offline(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(ROOT)
        script = RefreshScript.module()
        monkeypatch.setattr(script.time, "sleep", lambda _s: None)


class Network:
    """The refresh script's network, replaced: each URL fragment answers with a page."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.asked: list[str] = []

    def answer(self, url: str) -> Any:
        self.asked.append(url)
        for fragment, value in self.answers.items():
            if fragment in url:
                return value
        raise AssertionError(f"unexpected request: {url}")

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        refresh = RefreshScript.module().PackageIntelRefresh
        monkeypatch.setattr(
            refresh, "fetch_json_retrying", staticmethod(lambda url, **_: self.answer(url))
        )
        monkeypatch.setattr(refresh, "fetch_json", staticmethod(lambda url, **_: self.answer(url)))
        monkeypatch.setattr(refresh, "fetch", staticmethod(lambda url, **_: self.answer(url)))
        monkeypatch.setattr(
            refresh, "fetch_text_retrying", staticmethod(lambda url: self.answer(url))
        )


class TestRankedSources(Offline):
    def test_hex_reads_all_time_downloads(self, monkeypatch: pytest.MonkeyPatch) -> None:
        Network({"page=1": Pages.read("hex.json"), "page=": []}).install(monkeypatch)
        names, source = RefreshScript.module().PackageIntelRefresh.hex_pm()
        assert names == [("jason", 219403885), ("certifi", 180698584), ("idna", 179263639)]
        assert source == "https://hex.pm/api/packages"

    def test_hackage_reads_its_download_table(self, monkeypatch: pytest.MonkeyPatch) -> None:
        Network({"packages/top": Pages.read("hackage.json")}).install(monkeypatch)
        names, _ = RefreshScript.module().PackageIntelRefresh.hackage()
        assert names[:2] == [("git-annex", 1982), ("pandoc", 1602)]
        assert len(names) == 5

    def test_artifact_hub_reads_stars_and_keeps_the_best_of_a_repeated_name(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repeated = Pages.read("artifacthub.json")
        repeated["packages"].append({**repeated["packages"][0], "stars": 5})
        Network({"search": repeated}).install(monkeypatch)
        names, _ = RefreshScript.module().PackageIntelRefresh.artifact_hub()
        assert dict(names) == {"kube-prometheus-stack": 1237, "cert-manager": 999, "argo-cd": 847}

    def test_terraform_reads_provider_downloads(self, monkeypatch: pytest.MonkeyPatch) -> None:
        Network({"number%5D=1&": Pages.read("terraform.json"), "number%5D=": {"data": []}}).install(
            monkeypatch
        )
        names, _ = RefreshScript.module().PackageIntelRefresh.terraform_providers()
        assert names == [("aws", 8659723560), ("random", 3662037886), ("google", 2912301379)]

    def test_galaxy_reads_download_counts_and_sorts_them(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        Network({"index/": Pages.read("galaxy.json")}).install(monkeypatch)
        names, _ = RefreshScript.module().PackageIntelRefresh.galaxy()
        assert names == [
            ("consensus.matomo", 16),
            ("koichirok.postconf", 15),
            ("peshev.docker", 8),
        ]

    def test_julia_sums_the_requests_for_each_named_package(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        registry = (Pages.DIRECTORY / "julia_registry.toml").read_bytes()
        logs = (Pages.DIRECTORY / "julia_requests.csv.gz").read_bytes()
        Network({"Registry.toml": registry, "package_requests": logs}).install(monkeypatch)
        names, _ = RefreshScript.module().PackageIntelRefresh.julia()
        expected: dict[str, int] = {}
        uuids = tomllib.loads(registry.decode())["packages"]
        for row in csv.DictReader(io.StringIO(gzip.decompress(logs).decode())):
            if row["status"] in {"200", "302"}:
                name = uuids[row["package_uuid"]]["name"].lower()
                expected[name] = expected.get(name, 0) + int(row["request_count"])
        assert expected
        assert dict(names) == expected

    def test_docker_hub_joins_the_official_listing_and_the_searches(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        Network(
            {
                "repositories/library": Pages.read("hub_library.json"),
                "page=1": Pages.read("hub_search.json"),
                "page=2": {"results": []},
            }
        ).install(monkeypatch)
        names, _ = RefreshScript.module().PackageIntelRefresh.docker_hub()
        found = dict(names)
        assert found["nginx"] == 13643022660
        assert found["nginx/nginx-ingress"] == 1089031337
        assert found["espocrm"] == 256211

    def test_github_actions_reads_stars(self, monkeypatch: pytest.MonkeyPatch) -> None:
        Network({"&page=1": Pages.read("github_actions.json"), "&page=": {"items": []}}).install(
            monkeypatch
        )
        names, _ = RefreshScript.module().PackageIntelRefresh.github_actions()
        assert names == [
            ("lowlighter/metrics", 17492),
            ("kucherenko/jscpd", 6631),
            ("tidedra/zotero-arxiv-daily", 6178),
        ]


class TestIndexSources(Offline):
    def test_conda_lists_the_channel_in_its_own_order(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        body = (Pages.DIRECTORY / "conda_channeldata.json").read_bytes()
        Network({"channeldata": body}).install(monkeypatch)
        names, _, size, step = RefreshScript.module().PackageIntelRefresh.conda()
        assert names == list(json.loads(body)["packages"])
        assert (size, step) == (4, 1)

    def test_swift_names_each_repository(self, monkeypatch: pytest.MonkeyPatch) -> None:
        urls = Pages.read("swift_packages.json")
        Network({"packages.json": urls}).install(monkeypatch)
        names, _, size, _ = RefreshScript.module().PackageIntelRefresh.swift()
        assert size == len(urls)
        assert names == [
            u.rstrip("/").removesuffix(".git").rsplit("/", 1)[-1].lower() for u in urls
        ]

    def test_cocoapods_names_every_pod_of_every_shard(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        shard = (Pages.DIRECTORY / "cocoapods_shard.txt").read_text(encoding="utf-8")
        network = Network({"all_pods_versions_": shard})
        network.install(monkeypatch)
        names, _, size, step = RefreshScript.module().PackageIntelRefresh.cocoapods()
        assert len(network.asked) == 16**3
        assert size == len({ln.split("/", 1)[0] for ln in shard.splitlines()})
        assert "Alamofire" in names
        assert step == 1


class TestTheStride(Offline):
    @pytest.mark.parametrize(
        ("size", "step"),
        [(1, 1), (999, 1), (1000, 1), (1001, 2), (2500, 3), (22538, 23), (35256, 36)],
    )
    def test_n_is_the_size_over_a_thousand_rounded_up(self, size: int, step: int) -> None:
        names = [f"name-{i}" for i in range(size)]
        sample, _, whole, found = RefreshScript.module().PackageIntelRefresh.sampled(
            names, "source"
        )
        assert (whole, found) == (size, step)
        assert found == math.ceil(size / 1000)
        assert sample == names[::step]
        assert len(sample) <= 1000

    def test_it_reaches_the_end_of_the_alphabet(self) -> None:
        names = sorted(f"{a}{b}" for a in "abcdefghijklmnopqrstuvwxyz" for b in "abcdefghij" * 20)
        sample, _, _, _ = RefreshScript.module().PackageIntelRefresh.sampled(names, "source")
        assert {n[0] for n in sample} == set("abcdefghijklmnopqrstuvwxyz")
