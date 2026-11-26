"""SI-O2, the benign-training guardrail: a benign unit trains only if it is established.

Established is a first registry publication at least 90 days old, or a name on a list the scanner ships (the popular names or the names known
to be real). No recorded first publication, on no list, is not established. The trainer reads the rule where benign rows enter (`--established`)."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from bench.model.established import Established

from cordon_scanner.intel.registries.popular import PackageIntel
from support import ROOT

sys.path.insert(0, str(ROOT / "bench" / "model"))

from verdict_train import VerdictTrain

NOW = datetime(2026, 11, 25, 12, 0, tzinfo=UTC)


class Days:
    @staticmethod
    def ago(days: float) -> str:
        return (NOW - timedelta(days=days)).isoformat()


class TestWhoIsEstablished:
    POPULAR = next(n for n in sorted(PackageIntel.POPULAR_PACKAGES["npm"]) if n.isalpha())

    def test_a_name_first_published_ninety_days_ago_is(self) -> None:
        assert Established.accepts("npm", "tiny-local-helper", Days.ago(90), NOW)

    def test_a_name_first_published_eighty_nine_days_ago_is_not(self) -> None:
        assert not Established.accepts("npm", "tiny-local-helper", Days.ago(89.9), NOW)

    def test_a_young_name_on_the_popular_list_is(self) -> None:
        assert Established.accepts("npm", self.POPULAR, Days.ago(1), NOW)

    def test_a_name_with_no_recorded_publication_and_on_no_list_is_not(self) -> None:
        assert not Established.accepts("npm", "tiny-local-helper", None, NOW)

    @pytest.mark.parametrize("text", ["", "yesterday", "2026-13-45", "00:00"])
    def test_a_first_publication_that_is_not_a_time_is_not_an_age(self, text: str) -> None:
        assert not Established.accepts("npm", "tiny-local-helper", text, NOW)

    def test_a_zulu_time_and_a_time_with_no_zone_are_read(self) -> None:
        assert Established.accepts("npm", "tiny-local-helper", "2026-01-01T00:00:00Z", NOW)
        assert Established.accepts("npm", "tiny-local-helper", "2026-01-01T00:00:00", NOW)

    def test_the_list_is_the_ecosystems_own(self) -> None:
        assert not Established.accepts("pypi", self.POPULAR + "-no-such-package", None, NOW)


class Corpus:
    """A benign file of four units and a malware file of one, and what the trainer is told about them."""

    UNITS = (
        "npm/fresh-helper-1.0.0.tgz",
        "npm/old-helper-1.0.0.tgz",
        "npm/unknown-helper-1.0.0.tgz",
        f"npm/{TestWhoIsEstablished.POPULAR}-1.0.0.tgz",
    )

    @staticmethod
    def row(unit: str) -> dict:
        return {"file": unit, "findings": [], "verdict": {"package": {"files": 3.0}}}

    @classmethod
    def arguments(cls, tmp_path: Path, established: Path | None) -> argparse.Namespace:
        benign, malware, corpus = (
            tmp_path / "benign.jsonl",
            tmp_path / "malware.jsonl",
            tmp_path / "corpus.txt",
        )
        benign.write_text(
            "".join(json.dumps(cls.row(u)) + "\n" for u in cls.UNITS), encoding="utf-8"
        )
        malware.write_text(
            json.dumps(
                {
                    **cls.row("npm/evil-1.0.0.tgz"),
                    "findings": [
                        ["MALWARE.X.001", "critical", "high", "malicious", "p/i.js", 1, "h"]
                    ],
                }
            )
            + "\n",
            encoding="utf-8",
        )
        corpus.write_text("\n".join(cls.UNITS) + "\n", encoding="utf-8")
        return argparse.Namespace(
            adjudication=[],
            benchmark=None,
            benign=benign,
            corpus=corpus,
            eco=None,
            family_map=None,
            features=[],
            labelled=[],
            malware=malware,
            override=[],
            registry=[],
            registry_scans=[],
            registry_units=None,
            established=established,
        )

    @staticmethod
    def ages(tmp_path: Path) -> Path:
        path = tmp_path / "ages.jsonl"
        lines = [
            {"file": "npm/fresh-helper-1.0.0.tgz", "first_published": Days.ago(10)},
            {"file": "npm/old-helper-1.0.0.tgz", "first_published": Days.ago(400)},
            {
                "file": f"npm/{TestWhoIsEstablished.POPULAR}-1.0.0.tgz",
                "first_published": Days.ago(2),
            },
        ]
        path.write_text(
            "".join(json.dumps(line) + "\n" for line in lines) + "not json\n", encoding="utf-8"
        )
        return path

    @staticmethod
    def benign(data: list[dict]) -> set[str]:
        return {row["file"] for row in data if row["label"] == 0}


class TestTheTrainerTakesOnlyEstablishedBenignUnits:
    def test_with_the_ages_a_fresh_and_an_unknown_unit_do_not_train(self, tmp_path: Path) -> None:
        data, _ = VerdictTrain.load(Corpus.arguments(tmp_path, Corpus.ages(tmp_path)))
        assert Corpus.benign(data) == {
            "npm/old-helper-1.0.0.tgz",
            f"npm/{TestWhoIsEstablished.POPULAR}-1.0.0.tgz",
        }
        assert sorted(VerdictTrain.not_established) == [
            "npm/fresh-helper-1.0.0.tgz",
            "npm/unknown-helper-1.0.0.tgz",
        ]

    def test_without_the_ages_nothing_is_left_out_as_before(self, tmp_path: Path) -> None:
        data, _ = VerdictTrain.load(Corpus.arguments(tmp_path, None))
        assert Corpus.benign(data) == set(Corpus.UNITS)
        assert VerdictTrain.not_established == []

    def test_malware_is_never_asked_its_age(self, tmp_path: Path) -> None:
        data, _ = VerdictTrain.load(Corpus.arguments(tmp_path, Corpus.ages(tmp_path)))
        assert any(row["label"] == 1 for row in data)

    def test_a_second_load_starts_its_list_again(self, tmp_path: Path) -> None:
        VerdictTrain.load(Corpus.arguments(tmp_path, Corpus.ages(tmp_path)))
        VerdictTrain.load(Corpus.arguments(tmp_path, None))
        assert VerdictTrain.not_established == []
