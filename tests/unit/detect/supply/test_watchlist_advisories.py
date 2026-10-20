"""Records for the registries Cordon follows through watch-lists (cordon-backend task 22): a Helm chart
is matched only from a repository its record names, and an image pinned by digest by that digest."""

from __future__ import annotations

from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.detect.supply.advisory import MALICIOUS_RULE, AdvisoryDetector
from cordon_scanner.foundation.config import Config
from cordon_scanner.intel.advisories.advisories import Advisory, AdvisoryDatabase

DIGEST = "sha256:" + "c" * 64


class WatchlistKit:
    @staticmethod
    def rules(project: Path, *records: Advisory) -> set[str]:
        config = Config.default().with_overrides(use_cache=False)
        detector = AdvisoryDetector(AdvisoryDatabase(records))
        return {f.rule_id for f in Scanner(config, detectors=(detector,)).scan(project).findings}

    @staticmethod
    def chart(root: Path, repository: str) -> Path:
        root.mkdir(parents=True, exist_ok=True)
        (root / "Chart.yaml").write_text(
            "apiVersion: v2\nname: app\nversion: 1.0.0\ndependencies:\n"
            f"  - name: valkey\n    version: 3.0.1\n    repository: {repository}\n",
            encoding="utf-8",
        )
        return root

    @staticmethod
    def helm_record() -> Advisory:
        return Advisory(
            ecosystem="helm",
            name="valkey",
            versions=("3.0.1",),
            malicious=True,
            summary="s",
            identifier="CORDON-HELM-0123456789ABCDEF0123",
            repositories=(
                "https://charts.bitnami.com/bitnami",
                "oci://registry-1.docker.io/bitnamicharts",
            ),
        )

    @staticmethod
    def image(root: Path, reference: str) -> Path:
        root.mkdir(parents=True, exist_ok=True)
        (root / "Dockerfile").write_text(f"FROM {reference}\nRUN true\n", encoding="utf-8")
        return root

    @staticmethod
    def image_record() -> Advisory:
        return Advisory(
            ecosystem="image",
            name="o/server",
            versions=("1.2.0", DIGEST),
            malicious=True,
            summary="s",
            identifier="CORDON-IMAGE-0123456789ABCDEF0123",
        )


class TestHelmCharts:
    def test_a_chart_from_the_repository_the_record_names_is_matched(self, tmp_path) -> None:
        for spelling in (
            "https://charts.bitnami.com/bitnami/",
            "oci://registry-1.docker.io/bitnamicharts",
        ):
            project = WatchlistKit.chart(tmp_path / spelling.split("/")[2], spelling)
            assert MALICIOUS_RULE in WatchlistKit.rules(project, WatchlistKit.helm_record()), (
                spelling
            )

    def test_the_same_chart_name_from_another_repository_is_not(self, tmp_path) -> None:
        project = WatchlistKit.chart(tmp_path / "p", "https://charts.example.org/stable")
        assert MALICIOUS_RULE not in WatchlistKit.rules(project, WatchlistKit.helm_record())


class TestImages:
    def test_an_image_pinned_by_the_records_digest_is_matched(self, tmp_path) -> None:
        project = WatchlistKit.image(tmp_path / "p", f"o/server@{DIGEST}")
        assert MALICIOUS_RULE in WatchlistKit.rules(project, WatchlistKit.image_record())

    def test_an_image_by_the_records_tag_is_matched(self, tmp_path) -> None:
        project = WatchlistKit.image(tmp_path / "p", "o/server:1.2.0")
        assert MALICIOUS_RULE in WatchlistKit.rules(project, WatchlistKit.image_record())

    def test_another_digest_of_the_same_image_is_not(self, tmp_path) -> None:
        project = WatchlistKit.image(tmp_path / "p", "o/server@sha256:" + "d" * 64)
        assert MALICIOUS_RULE not in WatchlistKit.rules(project, WatchlistKit.image_record())
