"""M2: FIRST's EPSS probability beside the known-exploited marks, offline."""

from __future__ import annotations

import gzip

import pytest

from cordon_scanner.intel import exploited
from cordon_scanner.intel.exploited import Epss


class TestTheData:
    def test_it_ships_and_verifies(self) -> None:
        Epss.scores.cache_clear()
        scores = Epss.scores()
        assert len(scores) > 100_000
        probability, percentile = scores["CVE-2021-44228"]
        assert probability > 0.9 and percentile > 0.99

    def test_the_highest_of_several_cves_is_used(self) -> None:
        found = Epss.lookup({"CVE-2021-44228", "CVE-1999-0001"})
        assert found is not None and found.cve == "CVE-2021-44228"
        assert "chance of exploitation" in found.describe()

    def test_an_unscored_cve(self) -> None:
        assert Epss.lookup({"CVE-2099-99999"}) is None


class TestParsing:
    def test_firsts_format(self) -> None:
        data = gzip.compress(
            b"#model_version:v2026.06.15,score_date:2026-10-06T12:00:23Z\n"
            b"cve,epss,percentile\nCVE-2024-0001,0.01234,0.55\nnot,a,row\n"
        )
        assert Epss._parse(data) == {"CVE-2024-0001": (0.01234, 0.55)}

    def test_an_empty_file_is_refused(self) -> None:
        with pytest.raises(ValueError):
            Epss._parse(gzip.compress(b"cve,epss,percentile\n"))

    def test_only_the_allowed_host_is_fetched(self, monkeypatch) -> None:
        monkeypatch.setattr(exploited, "EPSS_URL", "https://example.invalid/epss.csv.gz")
        with pytest.raises(ValueError, match="allowlist"):
            Epss.fetch()
